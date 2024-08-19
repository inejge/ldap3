use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use crate::adapters::Adapter;
use crate::controls::Control;
use crate::ldap::Ldap;
use crate::parse_filter;
use crate::protocol::LdapOp;
use crate::result::{LdapError, LdapResult, Result};

use tokio::sync::{mpsc, Mutex};
use tokio::time;

use lber::common::TagClass;
use lber::structure::StructureTag;
use lber::structures::{Boolean, Enumerated, Integer, OctetString, Sequence, Tag};

/// Possible values for search scope.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Scope {
    /// Base object; search only the object named in the base DN.
    Base = 0,
    /// Search the objects immediately below the base DN.
    OneLevel = 1,
    /// Search the object named in the base DN and the whole subtree below it.
    Subtree = 2,
}

/// Possible values for alias dereferencing during search.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum DerefAliases {
    /// Never dereference.
    #[default]
    Never = 0,
    /// Dereference while retrieving objects according to search scope.
    Searching = 1,
    /// Dereference while finding the base object.
    Finding = 2,
    /// Always dereference.
    Always = 3,
}

#[derive(Debug)]
pub enum SearchItem {
    Entry(StructureTag),
    Referral(StructureTag),
    Done(LdapResult),
}

/// Wrapper for the internal structure of a result entry.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ResultEntry(pub StructureTag, pub Vec<Control>);

impl ResultEntry {
    #[doc(hidden)]
    pub fn new(st: StructureTag) -> ResultEntry {
        ResultEntry(st, vec![])
    }

    /// Returns true if the enclosed entry is a referral.
    pub fn is_ref(&self) -> bool {
        self.0.id == 19
    }

    /// Returns true if the enclosed entry is an intermediate message.
    pub fn is_intermediate(&self) -> bool {
        self.0.id == 25
    }
}

/// Additional parameters for the Search operation.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct SearchOptions {
    pub deref: DerefAliases,
    pub typesonly: bool,
    pub timelimit: i32,
    pub sizelimit: i32,
}

impl SearchOptions {
    /// Create an instance of the structure with default values.
    pub fn new() -> Self {
        SearchOptions {
            ..Default::default()
        }
    }

    /// Set the method for dereferencing aliases.
    pub fn deref(mut self, d: DerefAliases) -> Self {
        self.deref = d;
        self
    }

    /// Set the indicator of returning just attribute names (`true`) vs. names and values (`false`).
    pub fn typesonly(mut self, typesonly: bool) -> Self {
        self.typesonly = typesonly;
        self
    }

    /// Set the time limit, in seconds, for the whole search operation.
    ///
    /// This is a server-side limit of the elapsed time for performing the operation, _not_ a
    /// network timeout for retrieving result entries or the result of the whole operation.
    pub fn timelimit(mut self, timelimit: i32) -> Self {
        self.timelimit = timelimit;
        self
    }

    /// Set the size limit, in entries, for the whole search operation.
    pub fn sizelimit(mut self, sizelimit: i32) -> Self {
        self.sizelimit = sizelimit;
        self
    }
}

/// Parsed search result entry.
///
/// While LDAP attributes can have a variety of syntaxes, they're all returned in
/// search results as octet strings, without any associated type information. A
/// general-purpose result parser could leave all values in that format, but then
/// retrieving them from user code would be cumbersome and tedious.
///
/// For that reason, the parser tries to convert every value into a `String`. If an
/// attribute can contain unconstrained binary strings, the conversion may fail. In that case,
/// the attribute and all its values will be in the `bin_attrs` hashmap. Since it's
/// possible that a particular set of values for a binary attribute _could_ be
/// converted into UTF-8 `String`s, the presence of such an attribute in the result
/// entry should be checked for both in `attrs` and `bin_atrrs`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SearchEntry {
    /// Entry DN.
    pub dn: String,
    /// Attributes.
    pub attrs: HashMap<String, Vec<String>>,
    /// Binary-valued attributes.
    pub bin_attrs: HashMap<String, Vec<Vec<u8>>>,
}

impl SearchEntry {
    /// Parse raw BER data and convert it into attribute map(s).
    ///
    /// __Note__: this function will panic on parsing error.
    pub fn construct(re: ResultEntry) -> SearchEntry {
        let mut tags =
            re.0.match_id(4)
                .and_then(|t| t.expect_constructed())
                .expect("entry")
                .into_iter();
        let dn = String::from_utf8(
            tags.next()
                .expect("element")
                .expect_primitive()
                .expect("octet string"),
        )
        .expect("dn");
        let mut attr_vals = HashMap::new();
        let mut bin_attr_vals = HashMap::new();
        let attrs = tags
            .next()
            .expect("element")
            .expect_constructed()
            .expect("attrs")
            .into_iter();
        for a_v in attrs {
            let mut part_attr = a_v
                .expect_constructed()
                .expect("partial attribute")
                .into_iter();
            let a_type = String::from_utf8(
                part_attr
                    .next()
                    .expect("element")
                    .expect_primitive()
                    .expect("octet string"),
            )
            .expect("attribute type");
            let mut any_binary = false;
            let values = part_attr
                .next()
                .expect("element")
                .expect_constructed()
                .expect("values")
                .into_iter()
                .map(|t| t.expect_primitive().expect("octet string"))
                .filter_map(|s| {
                    if let Ok(s) = std::str::from_utf8(s.as_ref()) {
                        return Some(s.to_owned());
                    }
                    bin_attr_vals
                        .entry(a_type.clone())
                        .or_insert_with(Vec::new)
                        .push(s);
                    any_binary = true;
                    None
                })
                .collect::<Vec<String>>();
            if any_binary {
                bin_attr_vals.get_mut(&a_type).expect("bin vector").extend(
                    values
                        .into_iter()
                        .map(String::into_bytes)
                        .collect::<Vec<Vec<u8>>>(),
                );
            } else {
                attr_vals.insert(a_type, values);
            }
        }
        SearchEntry {
            dn,
            attrs: attr_vals,
            bin_attrs: bin_attr_vals,
        }
    }
}

// Not really, IMO
#[allow(rustdoc::invalid_html_tags)]
/// Possible states of a `SearchStream`.
///
/// ## `SearchStream` call/state conceptual diagram
///
/// <div>
/// <img src="data:image/png;base64,
/// iVBORw0KGgoAAAANSUhEUgAAAbAAAAFACAYAAADd3CkzAAAABHNCSVQICAgIfAhk
/// iAAAAAlwSFlzAAAN1wAADdcBQiibeAAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3Nj
/// YXBlLm9yZ5vuPBoAACAASURBVHic7d17VFTl/j/w9zhchAABlRQQBRKtFJSLQqkh
/// qJiShTqD4iWz4+2U6VGXSoUXTO2oqa2+mWkd7Zhl2YklmubdVEwwCbIjqFw8COIV
/// BOSiDjy/P1zsn9OAIgKbPfN+rcVazH6e/Vw+wHz2fvaejUoIIUBERKQwLeQeABHR
/// g4QQ2Lp1K6ZMmQKtVoszZ84Y1Jk+fToOHTpU7z50Oh20Wi3S09Mfe9+vvvoK//zn
/// P+vdNzUcJjAFiomJQWxsbKP2sXPnToSHhzdqH1S7cePG4d///rfcw5DF9u3b8fbb
/// b8PT0xMDBgyAo6OjQZ2EhATk5eXVu4+qqiocOHAAt27deux9U1NTkZCQUO++qeGY
/// yT0AenwXL16EhYVFo/Zx8+bNGo98qWmkp6eje/fucg9DFkePHkVYWBjmzp1ba53k
/// 5OQn6sPCwgIFBQVP1AbJj2dgzczWrVsRGhoKX19fhIeHIy4uTipbtWoVtFotjh07
/// hsOHD0Or1UKr1erV+fnnnxEVFYWAgAAEBgYiOjoaJSUlen38+eef0Gq1uHz5Ml5/
/// /XX4+vpizJgxuHXrFvbu3QutVot169bhxo0bUh+NfcanBKtXr8bGjRvx0UcfoVev
/// XhgyZAhSUlL06ly5cgUzZ85E3759MXjwYHz33Xd6ZaNGjcKff/4pbbt06RIiIyOR
/// lpYGAPjHP/4BrVaLzMxMbN26VYp/UlJS00xSRqtXr4ZWq8VPP/2EkydPSnN/8EBq
/// 9uzZ0vaalhDnzJmDuLg4zJ07F35+ftBqtcjNzdWrM3r0aKmNmpYQS0tLER0djRdf
/// fBEBAQEYN24czp8/b1Bv06ZNCAoKwoABA3D48OEGiAA9Lp6BNSP79+/H5MmT8ckn
/// n6Bz5864cOECMjMzpfIXXngBHTt2xJUrV2BmZgaNRgMA6Nq1q14b3bt3x7hx43D3
/// 7l0sWbIE58+fx3/+8x+pzrVr17B9+3ZcvnwZwcHBGDhwIBITE3Hjxg14enpCo9Hg
/// yJEjyM7OlvpwcnJqoig0XydPnsSRI0cQFRWFmJgYrFu3DpGRkUhPT4dKpUJRURH6
/// 9OkDLy8vREdH4+rVq3j77beh0+kwZswYtGvXDl26dMGoUaOQlJQES0tLjB07Fp6e
/// nnj22WcBAIMHD0ZxcTGSk5Ph7e2NYcOGAQBcXFzknHqTCAoKQocOHXD9+nVUVVXV
/// +LsXFhaGoqIiTJ8+HYMGDUJISIheG/v27cM333yDt99+GwsXLsSCBQswbdo07Ny5
/// U6ozYsQI3Lt3D1FRUXjnnXcMxjF37lwkJCRg6dKlaNmyJU6ePInc3Fx4eXlJdU6e
/// PAl7e3u8++672LZtGzQaDXJycmBtbd3QYaGHEdRsLFu2TPj4+Dyy3tixY8XEiRPr
/// 1ObBgweFWq0WlZWVetsAiA0bNtS636ZNm4Sbm1ud+jAVGo1G+Pv7S6//+OMPAUDk
/// 5eUJIYT46KOPhKurqygvL5fqrFmzRvTo0UN6rdPpRP/+/cWkSZPEokWLxPPPPy9K
/// S0sN+vL39xf//Oc/G3E2zdeECRPE+PHjH1rHw8NDbNy40WB79+7dxdixY6XX33//
/// vbCzszOod+fOHQFAHDt2zKCsd+/eYsGCBbX2/Y9//EO4urqKe/fuCSGEuHnzpgAg
/// EhMTHzpmang8A2tG+vfvj4ULF6JPnz549dVXpaXEx3Hp0iWsWrUKycnJKC8vR3l5
/// OSorK1FUVAQHBwe9utVH91R33t7e0vft2rUDANy4cQPOzs5ISUmBlZUVFi1aJNXJ
/// zs5Geno6hBBQqVRQq9XYunUrevbsibKyMvz66688am9gf/0ZFRcX4+7du3W+bjxo
/// 0CCsXLkSaWlpePnllxEWFgZnZ2e9Os899xzMzO6/fTo6OsLS0hI3btxouElQnfAa
/// WDMSGBiIlJQUhISEYNu2bfDz88OsWbPqvP/du3cREhKC/Px8LF++HN999x2WLl0K
/// 4P5tw3/Vtm3bBhu7qbC0tJS+V6lUAO7f9g0AJSUlcHBw0Pvy9fXFokWLUFVVpbef
/// SqWCEAItWvBPsKE9mKj++jOqi9jYWGzfvh1t2rTBe++9B09PT+zbt0+vzoO/B9X9
/// PE4f1DB4BtbMPPfcc4iNjUVsbCzWr1+PGTNmYNWqVXpvdGZmZjUmpLS0NGRkZCAp
/// KUk62zpx4kStfVX/cdfE3Ny8xj6odl5eXrh16xbmzZtXa53KykqMGTMGAwYMgKur
/// KzQaDZKSkgzOwszMzFBZWdnYQ6ZaDB06FEOHDsUnn3yCYcOGYcOGDRg0aJDcw6K/
/// 4OFfM3L48GHprighBK5cuYJ27doZHKV7eHjg119/NfgcjKOjI1QqFY4fPw7g/nLi
/// hx9+WK+xeHh44OrVq0hISNA7e6DajRkzBgkJCdiwYYN0NH7hwgVs3bpVqhMbG4uc
/// nBysW7cOsbGxsLW1xVtvvWXQloeHBw4ePIjCwsImGz/dt23bNinud+7cQWFhoUnc
/// RKNETGDNyJkzZ+Dr64vWrVvj6aefxhdffIEvvvjCoN60adOkO9dUKhWWLVsGAOjQ
/// oQMWL16MESNGwMXFBT169MDYsWPrNZagoCC8/fbbGD58ONRqNUJDQ59obqbA29sb
/// 3377LRYvXgxbW1s4OjqiR48e0m3z+/fvx4oVK/DNN9/A1tYW5ubm+OabbxAXF4fN
/// mzfrtfX++++jrKwMLi4uUKlU+PHHH2WYUfPy9ddfS8uvWVlZmDRpElQqFdzc3Orc
/// RkxMDFQqlbQE2LdvX6hUKr2zqy1btqBt27ZwdXVF27Zt0aJFC7z//vsNPh96cirB
/// hdtm5e7du8jOzoa5uTk6dOgAc3Pzx26joKAA+fn58PDwgJWVVSOMkh4lLy8PpaWl
/// 6Nixo8H1Emr+bt26hdzcXLRp00a6WYeaHyYwIiJSJC4hEhGRIjGBERGRIjGBERGR
/// IjGBERGRIjGBERGRIjGBERGRIjGBERGRIjGBERGRIjGBERGRIvFp9E3oYU9/NyVy
/// PfyF8b+P8ZcXH37UcHgGRkREisQzMBmY6hFYczkCZ/zlxfhTQ+EZGBERKRITGBER
/// KRITGBERKRITGBERKRITGBERKRITGBERKRITGBERKVKDfQ6ssrISKSkpAABLS0t0
/// 6tQJNjY2tdafPn06IiIiEBIS0lBDIGr2UlJSkJ6eDjs7OwQGBsLR0VHuIREpVoOd
/// gZWUlMDf3x8vvfQSevbsCQcHB0RGRqKgoKDG+gkJCcjLy2uo7uulX79+OHr0qKxj
/// INPRp08fBAQEYPHixZg6dSo8PT2xa9cuuYdFpFgNvoT41VdfoaysDImJiUhLS0NE
/// RESN9ZKTkzFu3LiG7v6x/P7777h165asYyDTERUVhStXriAtLQ0XL15EREQExo8f
/// D51OJ/fQiBSpUa6BmZubw9fXFytWrMDRo0dx8uRJqWz27NnQarXQarU4dOhQjfuv
/// WrUKX375JeLi4tC/f38EBgZi48aNUnl6ejomTZqEwMBAvPbaa/jll18M2khJScGb
/// b76JoKAghISE4P/+7/+kssjISGi1WlRUVGDFihXSeHJzc/XaKC8vx4EDB5CWlvak
/// ISHC3//+d7Ru3RoA0KJFC4wcORKFhYXIycmReWREytSoN3H0798fKpUKJ06ckLaF
/// hYVBo9Hg6NGjyMrKqnG/X3/9FZ9++ik++OADjBo1ChMnTpTqZmRkICgoCEIILF68
/// GP369cOQIUOQlJQk7X/q1Cm88MILqKqqQkxMDCZPnoyffvpJKh85ciQ0Gg3MzMzw
/// 4osvQqPRQKPRwM7OTm8cV69excCBA/Hxxx83ZFiIAACpqalwcHCAi4uL3EMhUqRG
/// fZivpaUl7O3tcfXqVWnboEGDAADz589/6L6XLl1CZmamQVJZsWIFunXrho0bN0Kl
/// UiEsLAwXLlzA6tWrsW3bNgDAkiVL0K9fP2zatEnaLzIyUvpeo9EAACZOnIgXX3wR
/// w4YNq3EMFhYW8PPzg5ub22PMmujRcnNzsXLlSqxcuRKWlpZyD4dIkRr9afQ6nQ5q
/// tfqx9+vfv79B8gLuLw2q1WpER0dL2zIyMnD9+nXpdWpqKmbPnq23X32eBO3s7Izf
/// fvvtsfcjepiSkhK8+uqrGDx4MCZOnCj3cIgUq1ETWElJCUpKSuDq6vrY+7Zt27bW
/// Nj09PeHg4CBtGzBgAOzt7aXXt2/fhrW19eMPmKiR3blzBxEREWjTpg02b97Mf7FB
/// 9AQaNYHFxcVBpVIhNDT0sfet7Q/by8sLzs7OmDdvXq37du7cGampqY/sw8zM7KF3
/// gFVVVaGoqAiWlpZMiPTEKisrMW7cOJSWlmL//v2wsLCQe0hEitbgN3FcvXoVp06d
/// wvr16zFnzhy88cYb6NKlS4O1P2HCBGzevBl79+6Vtp0+fVrv8zSvv/46/vWvf+HA
/// gQMA7i9jbtmyxaAtT09P7NmzB2VlZTX2lZOTA0dHR8yaNavBxk+ma+LEiUhKSsK6
/// detw7do1ZGVlISsrCxUVFXIPjUiZRAMpLCwUAAQAYWVlJby9vcVHH30kdDqdVGfL
/// li1SnQe/OnTooNfW8OHDxVtvvVVrX2vWrBGtWrUS9vb2wsbGRjg6OorPP/9cKq+q
/// qhIxMTHC2tpatG7dWlhaWoq+ffsatHP48GHx/PPPCwsLCwFA/Pe//9Urz87OFgDE
/// lClT6hsWPdXzNVVyz1/u/q2trWv8/T969GiT9C/3/OXuX26mPv/GoBJCmf/fWwiB
/// 7OxsqFQqdOjQAWZmhquhlZWVyMrKgo2NDdq3by/DKPVVL4sqNORPTO75y92/3OSe
/// v9z9y83U598YFJvAlMjUf4Hlnr/c/ctN7vnL3b/cTH3+jYFPoyciIkViAiMiIkVi
/// AiMiIkViAiMiIkViAiMiIkViAiMiIkViAiMiIkViAiMiIkViAiMiIkVq9P8HRob4
/// LzTkxfjLi/GnhsIzMCIiUiQ+C9GE8Fls8mL85cX4Gx+egRERkSIxgRERkSIxgRER
/// kSIxgRERkSIxgRERkSIxgRERkSIxgRERkSIxgRERkSIxgRERkSIxgRERkSIxgRER
/// kSIxgRERkSIxgRERkSIxgRERkSIxgRERkSIxgRERkSIxgRERkSIxgRERkSIxgRER
/// kSIxgRERkSIxgRERkSIxgRERkSIxgRERkSIxgRERkSIxgRERkSIxgRERkSIxgRER
/// kSIxgRERkSIxgRERkSKZyT0Aanh5eXmYMGFCreUDBw402LZ582a4uLg04qhMB+Mv
/// L8bfdDCBGSEXFxdYWlrip59+qrH8wIEDeq+HDh3KP94GxPjLi/E3HSohhJB7ENTw
/// Tp8+jYCAANTlx5uYmIhevXo1wahMB+MvL8bfNPAamJHy8/PDkCFDHllv6NCh/ONt
/// BIy/vBh/08AzMCNWl6NQHn02HsZfXoy/8eMZmBF71FEojz4bF+MvL8bf+PEMzMg9
/// 7CiUR5+Nj/GXF+Nv3HgGZuRqOwrl0WfTYPzlxfgbN56BmYBTp04Z/LEmJSUhICBA
/// phGZFsZfXoy/8eIZmAkICAjA0KFDpddDhw7lH28TYvzlxfgbL56BmYgHrwVw7b/p
/// Mf7yYvyNExOYCQkPDwcA7Nq1S+aRmCbGX16Mv/FhAjMhp06dAgAun8iE8ZcX4298
/// mMCIiEiReBMHEREpEhMYEREpEv+dShNSqVRyD6FZkGvVmvG/j/GXF6/aNByegRER
/// kSLxDEwGpnoE1lyOwBl/eTH+1FB4BkZERIrEBEZERIrEBEZERIrEBEZERIrEBEZE
/// RIrEBEZERIrEBEZERIrUpJ8Du3jxIm7evGmwvWfPnmjRgrm0qVy+fBn5+flwd3eH
/// o6Oj3MMhahIVFRVITk5GVlYWWrVqhaCgILRp00buYdETaNKn0b/11lv49ttvUVFR
/// gTt37qBVq1YAgLy8PFhZWTXVMGRT/UFGuT7Iefz4cYwZMwY5OTkAgC1btmDs2LFN
/// 1r/c85e7f7nJPX+5+w8ODkZqairc3NxQXFyMGzduYNOmTRg5cmST9C/3/I1Rk572
/// fPrppygoKMC7776Lp59+GgUFBSgoKDCJ5NUcODg4IDY2FmfPnpV7KERNbv369bhx
/// 4wZSU1ORlZWFKVOm4G9/+xsqKyvlHhrVU7Natzt79iy0Wi1+++03DB06FIGBgVi5
/// cqXeEcucOXMQFxeHuXPnws/PD1qtFrm5uXrtpKenY9KkSQgMDMRrr72GX375xaCv
/// WbNmYc+ePfj0008RFBSEl156Cbt379arc+HCBRw4cAC3b99unAk3seeffx6vv/46
/// unTpIvdQiJpc165doVarAdw/GxowYACKiopw48YNmUdG9dWsEtj169exfft2zJ07
/// FxMnTsSoUaMQHR2Nffv2SXX27duHt956C/b29li4cCHOnz+PadOmSeUZGRkICgqC
/// EAKLFy9Gv379MGTIECQlJen1tXfvXsTExCA+Ph6TJk3C8OHDce7cOb06GzZswMCB
/// A5Gdnd24EyeiJlNZWYkLFy5g9erVeOGFF+Dk5CT3kKiemuXDfJcvX47evXsDAOLi
/// 4nD06FGEhYVJ5aGhoXj33XcBAHfu3MHf/vY3qWzFihXo1q0bNm7cCJVKhbCwMOmX
/// ddu2bXr9VFZWYs+ePbXeQOLi4gI/Pz8ucRIZiZ07d2LYsGEAAF9fX/z88898yK6C
/// NcsE1r17d+n79u3bG5zie3t7S9+3a9cOxcXFuHv3LiwsLJCSkgK1Wo3o6GipTkZG
/// Bq5fv27QzyuvvPLQux9nzpyJmTNnPslUiKgZCQ0NRWZmJi5fvozo6GhERETgl19+
/// kZYWSVmaZQKztLSUvlepVAZ37VhYWOiVA///zp6SkhJ4enrCwcFBqjNgwADY29sb
/// 9NO2bdsGHTcRNW/W1tbw8PCAh4cHvvnmG7i5ueHIkSMIDQ2Ve2hUD80ygT0JLy8v
/// ODs7Y968eU/cVnl5OSoqKmBnZ8cjNCIjU31pwFhu0jJFTXoTx/Xr15GVlYXCwkJU
/// VlYiKysLWVlZDfq5iAkTJmDz5s3Yu3evtO306dPYtWvXY7e1YMECODo6Gs1t5/fu
/// 3ZNiDvz/n8etW7dkHhlR4yotLcXKlSuRnZ2NqqoqXLlyBe+88w7s7OwQGBgo9/Co
/// npo0gc2dOxeenp5YvXo1rl27Bk9PT3h6eqK8vLzB+oiIiMDy5csRGRkJBwcH2Nra
/// YtCgQbh8+XKD9aFUmZmZ8PT0ROfOnQHc/yiBp6cn1q1bJ/PIiBrfpk2b4OHhATMz
/// M7Rv3x6JiYnYvn07nn76abmHRvXUpE/iaEpCCGRnZ0OlUqFDhw4wM5N/tdTUP4kv
/// 9/zl7l9ucs9f7v4BoKCgAPn5+bC3t4eLi0uT9t0c5m9sjDaBNUem/gss9/zl7l9u
/// cs9f7v7lZurzbwzN6oPMREREdcUERkREisQERkREisQERkREisQERkREisQERkRE
/// isQERkREisQERkREisQERkREiiT/85VMEP+BnrwYf3kx/tRQeAZGRESKxGchEhGR
/// IvEMjIiIFIkJjIiIFIkJzIQIIfivHGTE+MuL8Tc+TGAm5OTJk0hMTJR7GCaL8ZcX
/// 4298eBu9Cdm+fTtUKhUCAwPlHopJYvzlxfgbH96FaCKEEOjUqROqqqqQk5PDz+I0
/// McZfXoy/ceISoolITExETk4OcnNzuYwiA8ZfXoy/cWICMxHff/+99P327dtlHIlp
/// YvzlxfgbJy4hmoDq5ZOcnBwAgKurK5dRmhDjLy/G33jxDMwEVC+fVOMyStNi/OXF
/// +BsvJjAT8ODySTUuozQdxl9ejL/x4hKikRNCwN3dHf/73//0tnfo0AH/+9//uIzS
/// yBh/eTH+xo1nYEbu5MmTBn+8AHDp0iUuozQBxl9ejL9xYwIzcg9bKuEySuNj/OXF
/// +Bs3LiEasdqWT6pxGaVxMf7yYvyNH8/AjFhtyyfVuIzSuBh/eTH+xo8JzIjVZYmE
/// yyiNh/GXF+Nv/LiEaKQetXxSjcsojYPxlxfjbxp4BmakEhMTH/nHC3AZpbEw/vJi
/// /E0Dz8CIiEiReAZGRESKxARmQvr27Yu+ffvKPQyTxfjLi/E3PlxCNCHVF6r5I5cH
/// 4y8vxt/48AyMiIgUiQmMiIgUiQmMiIgUiQmMiIgUiQmMiIgUiQmMiIgUiQmMiIgU
/// iQmMiIgUiQmMiIgUiQmMiIgUiQmMiIgUiQmMiIgUiQmMiIgUiQmMiIgUiQmMiIgU
/// iQmMiIgUiQmMiIgUiQmMiIgUiQmMiIgUiQmMiIgUiQmMiIgUiQmMiIgUSSWEEHIP
/// wlS0atUKxcXFcg9DVnZ2digqKpKlb8af8ZebnPE3RkxgTUilUsk9hGZBrl85xv8+
/// xl9efMttOGZyD8AUmeovcHN5A2P85cX4U0PhNTAiIlIkJjAiIlIkJjAiIlIkJjAi
/// IlIkJjAiIlIkJjAiIlIkJjAiIlIkfg6MiEhBsrKyUFhYCB8fH5iZPfwtfPny5XB1
/// dcW4ceOaaHQNQwiB5ORknD9/Hvb29ggKCoK9vb1BPZ6BEREpSHh4OPz9/XHkyJFH
/// 1j1+/Dj++OOPBh/Dzp07ER4e3uDtVuvZsyeCgoKwZMkSTJo0Cc888wwOHjxoUI8J
/// jIhIIS5cuIBz585hwIABiI+Pl20cN2/exJkzZxqt/TfffBPXrl3D2bNncfHiRYSG
/// hmL8+PEG9ZjAiIgUIj4+Hr6+vhg7dmyNCez333/H8OHD4e/vjw8//NDgsV0///wz
/// oqKiEBAQgMDAQERHR6OkpEQq3717N2bPno0vv/wSvXv3Rnh4OHbt2iWV7927F1qt
/// FuvWrcONGzeg1Wqh1WoRGxur109CQgLGjBmDXr16YfTo0UhLSzMYa2RkJE6fPo2Y
/// mBj06tULYWFhSE5OBgBMnz5dWjI0MzPDiBEjcPnyZVy7dk2vDSYwIiKFiI+PR1hY
/// GAYNGoScnBykpqZKZfn5+ejXrx/at2+PJUuWIDEx0WCZcf/+/ejevTtiY2MRHR2N
/// /fv3Y8KECVL5+fPn8dlnn+Hrr7/GggUL0LNnTwwfPhx//vknAMDT0xMajQYBAQGw
/// traGRqOBRqPBSy+9JLVx+PBhhIaGwt3dHUuXLoW7uzsCAwORn5+vN5YffvgBU6ZM
/// QXZ2NqZPn45+/frhwoULNc47NTUV7du3R+vWrfULBDUZAMKUQy73/OXuX25yz1/u
/// /uX2pPO/fv26UKvV4ujRo0IIIXx8fERsbKxUvmjRIuHl5SWqqqqEEELcvn1b2Nra
/// ijlz5tTa5sGDB4VarRaVlZVCCCHWrFkj1Gq1uHTpklQnODhYTJkyRW+/TZs2CTc3
/// txrb7Nu3r3jzzTf1tgUHB4uFCxfqbWvRooXQarWPmLUQ586dE9bW1uLbb781KONd
/// iERECrB7927Y2NggKCgIABAWFoYdO3YgJiYGAJCWlgY/Pz/pqfdPPfUUunXrptfG
/// pUuXsGrVKiQnJ6O8vBzl5eWorKxEUVERHBwcAADt27eHq6urtE9AQAASExPrPM6U
/// lBTY2tpi/vz50raioiKkp6cb1B02bNhD2yooKMDw4cMxZswYjBo1yqCcCYyISAGq
/// r3m9/PLLAO4vGZ49exa5ublwdXVFWVkZ2rRpo7dPy5Ytpe/v3r2LkJAQ9OzZE8uX
/// L0f79u1x5swZREREQKfT1bgPAFhaWqK0tLROY9TpdCgvL4eTk5OUEIH717s8PDwM
/// 6js5OdXaVmlpKV555RV07twZn332WY11mMCIiJq5iooK7N27F5MnT0ZgYKC0fdKk
/// Sdi5cyemTZuGjh07SteqgPufpcrMzISfnx+A+2doGRkZSEpKkpLLiRMnDPq6fPky
/// KioqpESWnZ0NNzc3vTrm5uZ6Sa+amZkZPDw84OPjg5kzZ9Z7vnfu3MHw4cNhbW2N
/// bdu2Qa1W11iPN3EQETVzhw8fRmlpKWbPni3dOKHRaBAaGiqdmUVGRuLYsWM4fvw4
/// AGDLli3IycmR2nB0dIRKpZLKL126hA8//NCgr7KyMqxevRoAcPbsWcTHx0Oj0ejV
/// 8fDwwNWrV5GQkICqqiq9sgkTJmDlypX4/fffAQCVlZU4dOgQEhIS6jzfqKgoZGdn
/// Y/Xq1cjLy0NWVhaysrJw584d/YqPvIJGDQa8iM2bCGQk9/zl7l9uTzL/qVOnCm9v
/// b4PtGzZsEJaWlqK4uFgIIcTChQuFWq0WrVu3Fj4+PiIoKEjvJo7Y2Fhhbm4unJ2d
/// haOjo1i2bJkAIK5duyaEuH8TR+fOnUVwcLBwcHAQarVaTJkyReh0OoO+Z8yYIZyc
/// nAQAERISIm3X6XRi1qxZomXLlqJt27bC0tJSuLi4iD179ujt36JFC7Fv3z6Ddisr
/// K6VY/fUrOTlZr65KCBP9/94yqL64aqohl3v+cvcvN7nnL3f/cmuq+ZeUlCAvLw9e
/// Xl5o0cJwka2goAD5+fnw8PCAlZWVXtnatWvx5Zdf4syZMzh//jzatm2rdy3rceh0
/// OmRmZsLGxgbOzs7S/BsSr4ERERkRW1tbdO3atdZyR0dHODo6PrIdLy+vJxqHmZkZ
/// unTp8kRtPAqvgREREYD7dyDa2dnJPYw64xJiE+ISCpew5CT3/OXuX26mPv/GwDMw
/// IiJSJCYwIiJSJCYwIiJSJCYwIiJSJCYwIiJSJCYwIiJSJCYwIiJSJD6JQwaN8UgV
/// qjvGX16MPzUUnoE1ISV9wr2xyBkDxp/xlxtj0LD4JA4TwicByIvxlxfjb3x4BkZE
/// RIrEBEZERIrEBEZERIrEBEZERIrEBEZERIrEBEZERIrEBEZERIrEBEZERIrEBEZE
/// RIrEBEZERIrEBEZERIrEBEZERIrEBEZERIrEBEZERIrEBEZERIrEBEZERIrEBEZE
/// RIrEBEZERIrEBEZERIrEBEZERIrEBEZERIrEBEZERIrEBEZERIrEBEZERIrEBEZE
/// RIrEBEZERIrEBEZERIrEBEZERIrEBEZERIqkEkIIuQdhKlq1aoXi4mK5hyErOzs7
/// FBUVOygiRwAAEwFJREFUydI348/4y03O+BsjJrAmpFKp5B5CsyDXrxzjfx/jLy++
/// 5TYcM7kHYIpM9Re4ubyBMf7yYvypofAaGBERKRITGBERKRITGBERKRITGBERKRIT
/// GBERKRITGBERKRITGBERKVK9ElhWVhZOnz4NnU73yLrLly/Hli1b6tNNk9qwYQPW
/// rl0r9zDIyKWkpGDbtm3YvXs3CgoK5B4OKZAxvv/WJjc3F6dPn8atW7dqLK9XAgsP
/// D4e/vz+OHDnyyLrHjx/HH3/8UZ9uHmrnzp0IDw9vsPZOnz6NxMTEBmuP6K/69OmD
/// gIAALF68GFOnToWnpyd27dol97BIYYzx/fev9u3bhw4dOqBDhw4PnetjJ7CMjAyc
/// O3cOoaGhiI+Pf9Jx1tvNmzdx5swZ2fonelxRUVG4cuUK0tLScPHiRURERGD8+PF1
/// OpImAoALFy7g3LlzGDBggFG//zo5OWHZsmVITk5+aL3HTmA7duyAr68vxo0bV2MA
/// f//9dwwfPhz+/v748MMPDR4b8/PPPyMqKgoBAQEIDAxEdHQ0SkpKpPLdu3dj9uzZ
/// +PLLL9G7d2+Eh4frHaXu3bsXWq0W69atw40bN6DVaqHVahEbG6vXT0JCAsaMGYNe
/// vXph9OjRSEtL0yvPysrC6NGj4efnh/nz5+PevXs1zjclJQUHDhww2cffUMP5+9//
/// jtatWwMAWrRogZEjR6KwsBA5OTkyj4yUIj4+Hr6+vhg7dqyi338BIDIyEqdPn0ZM
/// TAx69eqFsLAwKWH16NED48aNg6en50Pj8dgJLD4+HmFhYRg0aBBycnKQmpoqleXn
/// 56Nfv35o3749lixZgsTERINTv/3796N79+6IjY1FdHQ09u/fjwkTJkjl58+fx2ef
/// fYavv/4aCxYsQM+ePTF8+HD8+eefAABPT09oNBoEBATA2toaGo0GGo0GL730ktTG
/// 4cOHERoaCnd3dyxduhTu7u4IDAxEfn4+AKCsrAx9+vQBAHzwwQe4ceMGtm3bVuN8
/// Y2JiMHDgQB4lU4NLTU2Fg4MDXFxc5B4KKYQxvP9W++GHHzBlyhRkZ2dj+vTp6Nev
/// Hy5cuPB4ARGP4fr160KtVoujR48KIYTw8fERsbGxUvmiRYuEl5eXqKqqEkIIcfv2
/// bWFrayvmzJlTa5sHDx4UarVaVFZWCiGEWLNmjVCr1eLSpUtSneDgYDFlyhS9/TZt
/// 2iTc3NxqbLNv377izTff1NsWHBwsFi5cKIQQ4osvvhAODg6ivLxcCCFEZWWl6NSp
/// kxg1apRBWzNnzhR+fn7i3r17tc6hrgCIxwy5UZF7/nL3/6BLly4JBwcH8cUXXzRZ
/// n3LPX+7+5fak8zeW999qLVq0EFqt9qFzLioqEgBEXFxcjeWP9TT63bt3w8bGBkFB
/// QQCAsLAw7NixAzExMQCAtLQ0+Pn5SU9dfuqpp9CtWze9Ni5duoRVq1YhOTkZ5eXl
/// KC8vR2VlJYqKiuDg4AAAaN++PVxdXaV9AgICHusGi5SUFNja2mL+/PnStqKiIqSn
/// p0vj7NatG1q2bAng/nJOQEBAjW2tWbOmzv0S1UVJSQleffVVDB48GBMnTpR7OKQQ
/// xvL++6Bhw4bVud2aPFYCq15zffnllwHcP2U9e/YscnNz4erqirKyMrRp00Zvn+ok
/// AQB3795FSEgIevbsieXLl6N9+/Y4c+YMIiIi9JboHtwHACwtLVFaWlqnMep0OpSX
/// l8PJyUn6gQD311s9PDwA3F9C/GsfLVu2rPU6GFFDuXPnDiIiItCmTRts3ryZ/2KD
/// 6sxY3n8f5OTkVKd2a1PnBFZRUYG9e/di8uTJCAwMlLZPmjQJO3fuxLRp09CxY0dp
/// rRS4/39/MjMz4efnB+D+EUJGRgaSkpKkyZ04ccKgr8uXL6OiokIKZHZ2Ntzc3PTq
/// mJub13hdyszMDB4eHvDx8cHMmTNrnEvHjh2xf/9+vW2ZmZkGfQDA7du3ce/ePb0f
/// BlF9VFZWYty4cSgtLcX+/fthYWEh95BIIYzp/bdBPXQB8gG7d+8WKpVK5OXl6W0f
/// Pny4GDx4sBBCiGPHjgm1Wi2OHTsmhBDiq6++EgCkNdicnByhUqlEfHy89Pq5554T
/// AMS1a9eEEPfXYAGIpUuXCiGE+O9//ytsbW3FN998o9fviRMnhFqtFsePH5fWb6st
/// W7ZMODs7i+TkZCGEEDqdThw8eFAcP35cCCFERkaGUKvV4vvvvxdCCLF//36hUqlq
/// vAYWHh4uAIi7d+/WNVS1Aq8BmPQ1mPHjx4uOHTuK5ORkkZmZKX1VX4ttbHLPX+7+
/// 5fYk8zem999qLVq0EPv27atxvhUVFSIzM1OkpqYKAGL9+vUiMzNT3Lp1S69enaM5
/// depU4e3tbbB9w4YNwtLSUhQXFwshhFi4cKFQq9WidevWwsfHRwQFBeldRIyNjRXm
/// 5ubC2dlZODo6imXLlhkEsHPnziI4OFg4ODgItVotpkyZInQ6nUHfM2bMEE5OTgKA
/// CAkJkbbrdDoxa9Ys0bJlS9G2bVthaWkpXFxcxJ49e6Q669evFxYWFqJ169bC3d1d
/// hIWFMYE1MrnnL3f/1tbW0hge/Kq+KN/Y5J6/3P3L7Unmb2zvv0I8PIGdOnWqxr+V
/// jz/+WK+eSoiG/4BTSUkJ8vLy4OXlhRYtDO/ULygoQH5+Pjw8PGBlZaVXtnbtWnz5
/// 5Zc4c+YMzp8/j7Zt29Z7+U6n0yEzMxM2NjZwdnY2uN5QXl6Oixcv4plnnoG5uXm9
/// +ngc1f03QsgVQe75y92/3OSev9z9y62p5q+U99+G8Fg3cdSVra0tunbtWmu5o6Mj
/// HB0dH9mOl5fXE43DzMwMXbp0qbXcysoKzz777BP1QUTUnCjl/bchNLun0bds2RJ2
/// dnZyD4OIyOQo7f23UZYQqWZcQuESlpzknr/c/cvN1OffGJrdGRgREVFdMIEREZEi
/// MYEREZEiMYEREZEiMYEREZEiMYEREZEiMYEREZEiNcqTOOjh+C805MX4y4vxp4bC
/// M7AmpKRPuDcWOWPA+DP+cmMMGhafxEFERIrEMzAiIlIkJjAiIlIkJjAiIlIkJjAi
/// IlIkJjAiIlIkJjAiIlIkJjAiIlIkPolDQa5fv46cnByD7W3atEHHjh2bbByjR4/G
/// /Pnz4ePj02R9NqWsrCwUFhbCx8cHZmaN8yei0+kQFRWF2NhYdO3atVH6MCaVlZVI
/// SUkBAFhaWqJTp06wsbGReVQkN56BKch//vMf+Pv7Y+DAgXpfa9eubfJxXLlypUn7
/// bErh4eHw9/fHkSNH6rX/mTNn4O/vj4qKilrrVFVV4cCBA7h161Y9R2laSkpK4O/v
/// j5deegk9e/aEg4MDIiMjUVBQIPfQSEZMYApjbm6OgoICva81a9bIPSyjkZGRgXPn
/// ziE0NBTx8fH1aqO0tBSnT59GVVVVrXUsLCxQUFCAwMDA+g7VJH311VcoKytDYmIi
/// 0tLSEBERIfeQSEZMYEamsLAQWq0W586dw4wZM+Dv749hw4YhMzNTqvOvf/0Lr776
/// KgIDAzFz5kwUFRXptXHq1CmMHDkSvr6+CA4OxgcffGDQz82bNzFx4kT4+flh8uTJ
/// KC4ubvS5NYUdO3bA19cX48aNqzWBbd++HVqtFv7+/njttddw4MABAMCff/4JrVaL
/// 9957DwAwbtw4aLVaTJkyRW//0aNHQ6vVQqvVIj09Xa/su+++w7vvvqu3TafTYezY
/// sUhKSpK2JSQkYMyYMejVqxdGjx6NtLS0J567Upibm8PX1xcrVqzA0aNHcfLkSaks
/// PT0db7zxBnr37o0RI0bgp59+0tt3zpw5iIuLw9y5c+Hn5wetVovc3Fy9Ounp6Zg0
/// aRICAwPx2muv4ZdffmmSedHjYwJToMLCQr2vyspKqay8vBzbt2/H2LFjce/ePcyc
/// ORPe3t64ePEiAGDx4sWYN28ewsPDsWjRImRmZuLll19G9SMxCwsLMXDgQHh4eODj
/// jz/GO++8g8uXLxuMYeHChejVqxfmzZuHn376CUuWLGmSuTe2+Ph4hIWFYdCgQcjJ
/// yUFqaqpe+dq1azF+/Hj06NEDy5cvx8CBA6VE5+TkBI1Gg9DQUABAREQENBoNXnnl
/// Fb02RowYgYiICGzfvh03btzQK+vYsSNWrFiBq1evStsOHTqEH3/8UbpWdvjwYYSG
/// hsLd3R1Lly6Fu7s7AgMDkZ+f3+DxaM769+8PlUqFEydOALh/5hsSEoKioiIsXrwY
/// zz//PF577TW9BLdv3z689dZbsLe3x8KFC3H+/HlMmzZNKs/IyEBQUBCEEFi8eDH6
/// 9euHIUOG6B08UDMiSDE+++wzAcDg68yZM1KdvLw8AUDMmjXLYP+ioiLRsmVL8e23
/// 30rbiouLhZWVlTh27JgQQoikpCQBQFy7dq3WcZibm4sPPvhAeh0bGyt69erVEFOU
/// 1fXr14VarRZHjx4VQgjh4+MjYmNjpfK7d+8KOzs7sXLlSr39qqqq9F7/+uuvAoAo
/// LS2tta87d+4IAFLcH2zrmWeeEZ988om0bcKECUKj0Uiv+/btK9588029/YKDg8XC
/// hQvrNlEFKiwsFADEDz/8oLfdwcFBzJ07VwghxOeffy7s7e1FWVmZVB4eHq4Xu+7d
/// u4uxY8dKr7///nthZ2cnvZ40aZLo06eP3s906tSpIjIyssHnRE+OdyEqjJmZGc6d
/// O6e3zdXV1aDesGHDDLalpaWhoqICx44dk+7oAgArKyukp6ejT58+ePbZZ9GhQwcE
/// BQVhxIgRCA0NRXBwMCwsLPTa8vb2lr5v3769wZmEEu3evRs2NjYICgoCAISFhWHH
/// jh2IiYkBAGRnZ6O4uBhDhgzR268h/7+VSqVCVFQUtm3bhrfffht37txBXFwcvvrq
/// K6lOSkoKbG1tMX/+fGlbUVGRwXKkKdDpdFCr1QDuL/15e3vDyspKKu/duze2bdum
/// t8+Dv7vt2rVDcXEx7t69CwsLC6SkpECtViM6Olqqk5GRgevXrzfyTKg+mMAURqVS
/// wcPD45H1nJycDLbdvn0bAODs7Kx3e/jcuXOlW+JtbGyQnJyMrVu3Yu/evVi9ejV6
/// 9OiB48ePw9LSUtrnrwlNGMF/5aleCnz55ZcBAPn5+Th79ixyc3Ph6uqK0tJSAIC1
/// tXWjjiMqKgpLlixBTk4OkpOToVarpTHpdDqUl5fDyckJDg4O0j6RkZF1+r0wJiUl
/// JSgpKZEO4EpLS9GyZUu9OlZWVigrK9Pb9uDvbvXBR/Xvb0lJCTw9PfViO2DAANjb
/// 2zfKHOjJMIGZkM6dOwMAXn31VXTr1q3Wem3atMGMGTMwY8YMnD9/Hl27dsWvv/6K
/// 4ODgJhpp06uoqMDevXsxefJkvTsDJ02ahJ07d2LatGnw9PSESqVCamoqOnXqVGtb
/// 1QcHOp2uXmPp0qUL/Pz88N133+G3337DyJEjpTddMzMzeHh4wMfHBzNnzqxX+8Yi
/// Li4OKpVKuubo5uaGQ4cO6dXJyMiAm5tbndv08vKCs7Mz5s2b16BjpcbBmzhMiJub
/// G0JCQjBjxgxpSaSsrAz//ve/pc91XbhwAQcPHpSOSKtvJnB2dpZn0E3k8OHDKC0t
/// xezZs6HRaKSvB2+nt7OzQ0REBN577z1kZ2cDuL909+OPP+q11alTJ6jVauzYsaPe
/// SWzMmDHYvHkzdu3ahTFjxuiVTZgwAStXrsTvv/8O4P6HfA8dOoSEhIR69aUkV69e
/// xalTp7B+/XrMmTMHb7zxBrp06QIA0Gg0yM7Oxtdffw3g/pL5d999h1GjRtW5/QkT
/// JmDz5s3Yu3evtO306dPYtWtXw06EGobM1+DoMXz22WfC3Nz8oXWqb+I4e/ZsjeVX
/// rlwRgwcPFmZmZqJdu3aiRYsWwsfHR1y+fFkIcf8mjrZt2worKyvh6uoqnnrqKfHh
/// hx/qtWFubi5+/vln6fXGjRuFu7v7E85OXlOnThXe3t4G2zds2CAsLS1FcXGxEEKI
/// goICERERIdRqtXj66aeFubm5WLBggcF+a9asEa6urkKlUglnZ2dp+/vvv1/jjTgD
/// Bw7U2//y5ctCrVYLNzc3UVlZqVem0+nErFmzRMuWLUXbtm2FpaWlcHFxEXv27GmI
/// UDRL1TdxABBWVlbC29tbfPTRR0Kn0+nV+/jjj4WVlZVo3bq1UKvVIioqSty5c0cq
/// 7969u1i7dq30+tixYwKAqKiokLatWbNGtGrVStjb2wsbGxvh6OgoPv/888afJD02
/// lRBGcPGCHltZWRkuXryIp59+Gq1bt9YrE0IgNzcXxcXFcHd3b/RrPkpUUVGB7Oxs
/// ODs7o1WrVrKMQafTITMzEzY2NnB2dm7Qm0mU7N69e9LPpr6PmxJCIDs7GyqVCh06
/// dGi0R4rRk2ECIyIiReI1MCIiUiQmMCIiUiQmMCIiUiQmMCIiUiQmMCIiUiQmMCIi
/// UiQmMCIiUiQmMCIiUiQmMCIiUiQmMCIiUiQmMCIiUiQmMCIiUiQmMCIiUiQmMCIi
/// UiQmMCIiUiQmMCIiUiQmMCIiUiQmMCIiUqT/B52Ay/eeLCmcAAAAAElFTkSuQmCC
/// ">
/// </div>
///
/// Columns depict method call chains. The __Inner__ row is the final call destination for
/// all stream variants. At the bottom of each column is the expected state before
/// the call to a method. Numbers in call site boxes are the points of state transitions.
///
/// `SearchStream` has two variants, direct and adapted, differentiated by the size of
/// the adapter vector. The direct version, with an empty vector, is the regular one;
/// the adapted version passes each method call through a chain of adapters before executing
/// the direct call. In the diagram, direct calls start from the top of the column, while adapted
/// calls start at the bottom.
///
/// Every `SearchStream` is created in the `Fresh` state, and the `start()` method is automatically
/// called. The `start()` method, although publicly visible so that adapter chaining can work, is
/// not meant for calls from user code. It will change the state from `Fresh` to `Active` at point (1),
/// when the protocol request is successfully written to the network socket. Any error in submitting
/// the request will change the state to `Error`. Calling `start()` in any state but `Fresh` will just
/// immediately return.
///
/// Iterating through the stream with `next()` requires the `Active` state, which turns into `Done`
/// when the final Search message is received. However, the transition must not be made in the
/// inner method, since the adapters may need to keep providing additional entries even when
/// the original operation is over. Therefore, point (2) occurs at the end of the first call
/// in the chain (for the adapted streams), or in the shim method (for the direct ones). As before,
/// any error will result in the `Error` state.
///
/// The `finish()` method may be called at any time. Adapters along the way can behave differently
/// according to the state, and the final direct call will change the state to `Closed` at (3). Calling
/// `finish()` on a stream in the `Closed` state will return a synthetic error-bearing `LdapResult`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamState {
    /// Stream which hasn't yet been initialized in `start()`.
    Fresh,
    /// Initialized stream which can be iterated through with `next()`.
    Active,
    /// Stream from which all entries have been retrieved.
    Done,
    /// Properly finalized stream on which `finish()` was called.
    Closed,
    /// Stream in an error state after some fallible operation.
    Error,
}

/// Asynchronous handle for obtaining a stream of search results. __*__
///
/// User code can't construct a stream directly, but only by using
/// [`streaming_search()`](struct.Ldap.html#method.streaming_search) or
/// [`streaming_search_with()`](struct.Ldap.html#method.streaming_search_with) on
/// an `Ldap` handle.
///
/// A streaming search should be used for situations where the expected
/// size of result entries varies considerably between searches, and/or
/// can rise above a few tens to hundreds of KB. This is more of a concern
/// for a long-lived process which is expected to have a predictable memory
/// footprint (i.e., a server), but can also help with one-off searches if
/// the result set is in the tens of thounsands of entries.
///
/// Once initiated, a streaming search is driven to the end by repeatedly calling
/// [`next()`](#method.next) until it returns `Ok(None)` or an error. Then, a call
/// to [`finish()`](#method.finish) will return the overall result of the search.
/// Calling `finish()` earlier will terminate search result processing in the
/// client; it is the user's responsibility to inform the server that the operation
/// has been terminated by performing an Abandon or a Cancel operation.
///
/// There are two variants of `SearchStream`, direct and adapted. The former calls
/// stream operations directly, while the latter first passes through a chain of
/// [adapters](adapters/index.html) given at the time of stream creation.
#[derive(Debug)]
pub struct SearchStream<'a, S, A> {
    pub(crate) ldap: Ldap,
    pub(crate) rx: Option<mpsc::UnboundedReceiver<(SearchItem, Vec<Control>)>>,
    state: StreamState,
    #[allow(clippy::type_complexity)]
    adapters: Vec<Arc<Mutex<Box<dyn Adapter<'a, S, A> + 'a>>>>,
    ax: usize,
    timeout: Option<Duration>,
    pub res: Option<LdapResult>,
}

impl<'a, S, A> SearchStream<'a, S, A>
where
    S: AsRef<str> + Send + Sync + 'a,
    A: AsRef<[S]> + Send + Sync + 'a,
{
    pub(crate) fn new(ldap: Ldap, adapters: Vec<Box<dyn Adapter<'a, S, A> + 'a>>) -> Self {
        SearchStream {
            ldap,
            rx: None,
            state: StreamState::Fresh,
            adapters: adapters.into_iter().map(Mutex::new).map(Arc::new).collect(),
            ax: 0,
            timeout: None,
            res: None,
        }
    }

    pub(crate) async fn start_inner(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: A,
    ) -> Result<()> {
        let opts = match self.ldap.search_opts.take() {
            Some(opts) => opts,
            None => SearchOptions::new(),
        };
        self.timeout = self.ldap.timeout;
        let req = Tag::Sequence(Sequence {
            id: 3,
            class: TagClass::Application,
            inner: vec![
                Tag::OctetString(OctetString {
                    inner: Vec::from(base.as_bytes()),
                    ..Default::default()
                }),
                Tag::Enumerated(Enumerated {
                    inner: scope as i64,
                    ..Default::default()
                }),
                Tag::Enumerated(Enumerated {
                    inner: opts.deref as i64,
                    ..Default::default()
                }),
                Tag::Integer(Integer {
                    inner: opts.sizelimit as i64,
                    ..Default::default()
                }),
                Tag::Integer(Integer {
                    inner: opts.timelimit as i64,
                    ..Default::default()
                }),
                Tag::Boolean(Boolean {
                    inner: opts.typesonly,
                    ..Default::default()
                }),
                match parse_filter(filter) {
                    Ok(filter) => filter,
                    _ => return Err(LdapError::FilterParsing),
                },
                Tag::Sequence(Sequence {
                    inner: attrs
                        .as_ref()
                        .iter()
                        .map(|s| {
                            Tag::OctetString(OctetString {
                                inner: Vec::from(s.as_ref()),
                                ..Default::default()
                            })
                        })
                        .collect(),
                    ..Default::default()
                }),
            ],
        });
        let (tx, rx) = mpsc::unbounded_channel();
        self.rx = Some(rx);
        if let Some(timeout) = self.timeout {
            self.ldap.with_timeout(timeout);
        }
        self.ldap.op_call(LdapOp::Search(tx), req).await.map(|_| {
            self.state = StreamState::Active;
        })
    }

    pub(crate) async fn next_inner(&mut self) -> Result<Option<ResultEntry>> {
        let item = if let Some(timeout) = self.timeout {
            let res = time::timeout(timeout, self.rx.as_mut().unwrap().recv()).await;
            if res.is_err() {
                let last_id = self.ldap.last_id;
                self.ldap.id_scrub_tx.send(last_id)?;
            }
            res?
        } else {
            self.rx.as_mut().unwrap().recv().await
        };
        let (item, controls) = match item {
            Some((item, controls)) => (item, controls),
            None => {
                self.rx = None;
                return Err(LdapError::EndOfStream);
            }
        };
        match item {
            SearchItem::Entry(tag) | SearchItem::Referral(tag) => {
                return Ok(Some(ResultEntry(tag, controls)))
            }
            SearchItem::Done(mut res) => {
                res.ctrls = controls;
                self.res = Some(res);
                self.rx = None;
            }
        }
        Ok(None)
    }

    pub(crate) async fn finish_inner(&mut self) -> LdapResult {
        if self.state != StreamState::Done {
            let last_id = self.ldap.last_id;
            if let Err(e) = self.ldap.id_scrub_tx.send(last_id) {
                warn!(
                    "error sending scrub message from SearchStream::finish() for ID {}: {}",
                    last_id, e
                );
            }
        }
        self.state = StreamState::Closed;
        self.rx = None;
        self.res.take().unwrap_or_else(|| LdapResult {
            rc: 88,
            matched: String::from(""),
            text: String::from("user cancelled"),
            refs: vec![],
            ctrls: vec![],
        })
    }

    /// Initialize a streaming Search.
    ///
    /// This method exists as an initialization point for search adapters, and is
    /// not meant for calling from regular user code. It must be public for user-defined
    /// adapters to work, but explicitly calling it on a `SearchStream` handle
    /// is a no-op: it will immediately return `Ok(())`.
    pub async fn start(&mut self, base: &str, scope: Scope, filter: &str, attrs: A) -> Result<()> {
        if self.state != StreamState::Fresh {
            return Ok(());
        }
        if self.ax == self.adapters.len() {
            let res = self.start_inner(base, scope, filter, attrs).await;
            if res.is_err() {
                self.state = StreamState::Error;
            }
            return res;
        }
        let adapter = self.adapters[self.ax].clone();
        let mut adapter = adapter.lock().await;
        self.ax += 1;
        let res = adapter.start(self, base, scope, filter, attrs).await;
        self.ax -= 1;
        if res.is_err() {
            self.state = StreamState::Error;
        }
        res
    }

    /// Fetch the next item from the result stream after executing the adapter chain
    /// if there is one.
    ///
    /// Returns `Ok(None)` at the end of the stream.
    #[allow(clippy::should_implement_trait)]
    pub async fn next(&mut self) -> Result<Option<ResultEntry>> {
        if self.state != StreamState::Active {
            return Ok(None);
        }
        if self.ax == self.adapters.len() {
            let res = self.next_inner().await;
            if res.is_err() {
                self.state = StreamState::Error;
            }
            return res;
        }
        let adapter = self.adapters[self.ax].clone();
        let mut adapter = adapter.lock().await;
        self.ax += 1;
        let res = adapter.next(self).await;
        self.ax -= 1;
        match res {
            Ok(None) if self.ax == 0 => self.state = StreamState::Done,
            Err(_) => self.state = StreamState::Error,
            _ => (),
        }
        res
    }

    /// Return the overall result of the Search.
    ///
    /// This method can be called at any time. If the stream has been read to the
    /// end, the return value will be the actual result returned by the server.
    /// Otherwise, a synthetic cancellation result is returned, and it's the user's
    /// responsibility to abandon or cancel the operation on the server.
    ///
    /// If the Search is adapted, this method will first execute the `finish()` methods of
    /// all adapters in the chain.
    pub async fn finish(&mut self) -> LdapResult {
        if self.state == StreamState::Closed {
            return LdapResult {
                rc: 80,
                matched: String::from(""),
                text: String::from("stream already finalized"),
                refs: vec![],
                ctrls: vec![],
            };
        }
        if self.ax == self.adapters.len() {
            return self.finish_inner().await;
        }
        let adapter = self.adapters[self.ax].clone();
        let mut adapter = adapter.lock().await;
        self.ax += 1;
        let res = adapter.finish(self).await;
        self.ax -= 1;
        res
    }

    /// Return a vector of the remaining adapters in the chain at the point
    /// of the method call. Adapter instances are cloned and collected into the
    /// resulting vector. The purpose of this method is to enable uniformly
    /// configured Search calls on the connections newly opened in an adapter.
    pub async fn adapter_chain_tail(&mut self) -> Vec<Box<dyn Adapter<'a, S, A> + 'a>> {
        let mut chain = vec![];
        for ix in self.ax..self.adapters.len() {
            let adapter = self.adapters[ix].clone();
            let adapter = adapter.lock().await;
            chain.push(adapter.as_ref().box_clone());
        }
        chain
    }

    /// Return the current state of the stream.
    pub fn state(&self) -> StreamState {
        self.state
    }

    /// Return the `Ldap` handle of the stream.
    ///
    /// Mutating the public elements of `Ldap` through the obtained handle can't affect
    /// the current operation _except_ in the `start()` chain of an adapted streaming
    /// Search, intentionally so.
    pub fn ldap_handle(&mut self) -> &mut Ldap {
        &mut self.ldap
    }
}

/// Parse the referrals from the supplied BER-encoded sequence.
pub fn parse_refs(t: StructureTag) -> Vec<String> {
    t.expect_constructed()
        .expect("referrals")
        .into_iter()
        .map(|t| t.expect_primitive().expect("octet string"))
        .map(String::from_utf8)
        .map(|s| s.expect("uri"))
        .collect()
}
