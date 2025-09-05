# An LDAP Primer

Copyright (c) 2022 Ivan Nejgebauer. Distributed under the Creative Commons
Attribution-NonCommercial-ShareAlike 4.0 International (CC-BY-NC-SA) license.

# 0. Foreword

"LDAP" stands for Lightweight Directory Access Protocol. If you don't recognize
the acronym, or don't find anything in the full name meaningful, this document
is probably not for you. It's a high-level introduction to a niche technical
topic.

With that out of the way, why another LDAP introduction? As the author of an
[LDAP library](https://crates.io/crates/ldap3), one thing that has long
bothered me was the inability to refer the non-knowledgeable reader to basic
documentation that I felt to be both approachable and complete enough. Existing
LDAP literature is famously hermetic, making the initial steps toward understanding
much more difficult than necessary; even the introductory texts can't resist
the temptation of using advanced terminology before having it explained.

The aspiration of this primer is to introduce the topic of LDAP well enough
to provide a foothold for further exploration, without requiring the reader's
previous familiarity with anything beyond JSON, TCP, and TLS.

# 1. Introduction

The term "LDAP" is used for two related but distinct concepts:

1. A database with a well-defined data model. ("We keep our user identities
   in LDAP.") The database and the service are often called a _directory_.
   It can be implemented as a separate specialized server, like OpenLDAP,
   or as part of a set of system components, like Active Directory.

2. The standardized protocol to access the database. ("Use LDAP to query
   Active Directory.") Since the protocol is standardized and the data model
   well-known, even a service with a radically different data store can
   use it to offer access to its data.

Developers need good working knowledge of both aspects to use LDAP
effectively. The principal difficulty with gaining that knowledge lies
in learning a sizeable set of interrelated concepts using rather alien
terminology, stemming from LDAP's roots in the X.500 standardization
effort. The IETF/ISO standard wars of the mid- to late 1980s are
now forgotten, but one can glimpse some of the reasons for the IETF's
decisive victory by perusing any available X.500 document and noting
the impenetrable text combined with a jungle of references to other
such documents.

This primer will try to lessen the pain by always being clear whether it's
talking about LDAP, the database or LDAP, the protocol, and introducing
the minimum of necessary terminology to explain any issue. For a deeper
understanding, familiarity with the original specifications is still
immensely useful, and the interested reader shouldn't shy away even from
the ISO/ITU-T standards. X.501 (The Directory: Models), 1993 edition, is
[available online](https://www.itu.int/rec/T-REC-X.501-199311-S/en).
If one makes peace with the style, it's evident that many LDAP concepts are
a simplified extrapolation of those in X.501.

# 2. The LDAP data model

## 2.1. Entries and attributes

Let's imagine a toy system for storing user identities. For each user there
will be a data set containing the username, a password, the user's full name
and their last name. (This is not very realistic; especially, the password
should _never_ be stored in clear text.) If there is a "John Doe" with the
username "john.doe" and password "secret", their data set represented as a
JSON object might look like this:

    {
        "username": "john.doe",
        "full_name": "John Doe",
        "last_name": "Doe",
        "password": "secret"
    }

To make the data closer to the LDAP model, one would first rename the keys.
Still keeping it in JSON:

    {
        "uid": "john.doe",
        "cn": "John Doe",
        "sn": "Doe",
        "userPassword": "secret"
    }

LDAP uses a different textual format, called LDIF (LDAP Data Interchange
Format.) Directly translating the above JSON to LDIF gives:

    uid: john.doe
    cn: John Doe
    sn: Doe
    userPassword: secret

In LDAP, a data set like this one is called an __entry__. An LDAP database is
a collection of entries. What were the keys in the JSON object are called
__attributes__ in LDAP. 

The above entry is incomplete. If filled out to a minimal complete form, it might
look like this:

    dn: uid=john.doe,ou=People,dc=example,dc=com
    objectClass: top
    objectClass: person
    objectClass: organizationalPerson
    objectClass: inetOrgPerson
    uid: john.doe
    cn: John Doe
    sn: Doe
    userPassword: secret

The `dn` line will be explained in the next section. Here, just note that
there are multiple lines starting with "objectClass". That's because most
LDAP attributes can have multiple values, which is represented in LDIF as separate
lines with the same attribute name. Attribute values in an entry form
a mathematical set: there must not be any duplicate values for a given attribute.

Attributes cannot exist without values; there's no concept in LDAP of a `null` value.

Attribute names can be more complicated than described here, and more will be
said in a later section.

## 2.2. Entry naming and organization

Entries in an LDAP database are logically organized as a tree, called the __directory
information tree__ (DIT), and every entry has a property describing its position
in the tree. The property is named `dn` for "distinguished name", and is unique
for an entry. Despite using the attribute syntax in the LDIF, it is *not* one of
the entry attributes. Let's repeat the full entry from the previous section
and highlight the naming attributes:

<pre><code><b>dn</b>: uid=john.doe,ou=People,<i>dc=example,dc=com</i>
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
<b>uid</b>: john.doe
cn: John Doe
sn: Doe
userPassword: secret
</code></pre>

A __distinguished name__ (DN) is a sequence of components describing the path
through the logical tree from its root to the entry itself. In the LDIF value
representation, the components are comma-separated and written left-to-right
from the entry to the root. (In the above DN, the component closest to the
root is "dc=com".) Each component is called a __relative distinguished name__
(RDN), and (in the simplest case, covered here) consists of a single attribute
name and a value. The attribute and the value of the leftmost RDN, which names
the entry, must exist in the entry itself. Above, the entry having the RDN
"uid=john.doe" means that it must have the attribute `uid` with the value
"john.doe".

Originally, the X.500 directory standard envisioned a distributed directory,
not unlike the domain name system, but with a much richer data model. For a
variety of reasons, this never happened, and the directories remained disparate.
The X.500 naming system has countries and registered organizations as DN root
elements, which wasn't well suited to domain names used for naming on the internet,
so a method of using domain names in DNs was standardized in RFC 2247 and is
predominantly used in LDAP today.

The DN above has the rightmost part in italic. That part directly corresponds
to the domain __example.com__. In a DIT organized with such a mapping, all entries
are at or below the domain, which is then called the __suffix__ or __naming context__.
A single DIT can contain multiple naming contexts.

There is a special entry at the very root of the DIT. It has an empty DN (i.e., `""`)
and is called the __root DSE__ (DSA Specific Entry; "DSA" stands for "directory
system agent", another name for the directory server.) It's used to store basic
configuration and capability data about the directory server.

## 2.3. Entry structure and schemas

The set of attributes in an entry is not arbitrary, but dictated by the entry's
__object classes__, each of which defines a set of mandatory and/or optional
attributes. One, and only one, of the entry's object classes is __structural__,
and ordinarily fixed for the lifetime of the entry. All other object classes are
__auxiliary__ and may be added to or removed from an entry. Object classes form
a hierarchy, in which all structural classes are ultimately derived from the
_top_ class. That's why there will always be an `objectClass` attribute with
that value in an entry.

In the John Doe entry used as an example, the (structural) class _inetOrgPerson_
is derived from _organizationalPerson_, in turn a descendant of  _person_, which mandates
the `cn` and `sn` attributes. Furthermore, `userPassword` is an optional attribute
of _person_, while `uid` is an optional attribute of _inetOrgPerson_, although
it's mandatory in this entry since it's a naming attribute.

Despite having descriptive names, object classes and attributes are actually
identified by __object identifiers__ (OIDs), which are arrays of integers, written
as decimal numbers separated by dots. For example, the identifier `2.5.4.3`
is mapped to two names: `cn` and `commonName`. The example entry used `cn`,
but could have used `commonName` for exactly the same purpose. Attribute names
are not case-sensitive: `commonName`, `commonname` and `COMMONNAME` refer to
the same attribute.

Object identifiers are one of the main visible legacies of LDAP's X.500 origins.
The main branches of the OID namespace are controlled by the international
standards organizations, ISO and ITU-T (formerly CCITT.) Obtaining one's own OID
subtree for experimentation or customization is a somewhat involved process, but
is also possible without bureaucracy by [using a UUID](https://oidref.com/2.25)
in the `2.25` OID arc.

Aside from the identifier and the names, an attribute definition also describes
the syntax of attribute values and the ways those values can be compared for
(in)equality, ordering and substring matching, by specifying the OIDs of the
corresponding syntax and matching rules. Knowing the rules for a particular
attribute is necessary for constructing searches, since not all search operations
are compatible with all attribute types.

A collection of attribute and object class definitions is called a __schema__. A
directory will support a number of standardized schemas and provide the ways to
extend the schema collection. It's important to note that standard attribute
definitions should not be changed, because external tools and integrations might
depend on them.

# 3. LDAP, the protocol

## 3.1. Connection lifecycle and basic authentication

LDAP standards describe the transport options, operations and message formats of
the protocol. The latter two are tightly coupled to the data model, so understanding
the model makes learning the protocol much easier. Contrary to the many early internet
protocols, LDAP has a binary encoding, necessitating the use of language-specific
APIs or precompiled access tools to communicate with the server.

LDAP uses TCP and port 389 to listen to client connection requests. Unless upgraded
later, those connections are completely in the clear, and vulnerable to eavesdropping.
It is therefore strongly recommended to secure the connection by using TLS or some
other method, like Kerberos. Here one encounters some long-standing unaddressed
specification deficiencies.

The only standardized way of activating TLS is by first connecting in the clear to
port 389, then issuing a special LDAP operation which requests the TLS handshake. This
method, called StartTLS, is considered less secure than unconditional TLS establishment,
and is discouraged in current usage. There is a de-facto standard for straight TLS
connections, where the server listens on port 636. It's supported by everyone, but for
some reason was never standardized, and it's doubtful that it will ever be.

LDAP has a family of URL schemes for specifying connection
and search parameters. In the most basic usage, the scheme part is __ldap__ for clear
connections, __ldaps__ for unconditional TLS, and __ldapi__ for UNIX domain sockets
(definitely nonstandard but widely available on Unix-like systems.) The host part of
the URL specifies the hostname or IP address of the server; the port, if present,
likewise, with the default value depending on the scheme (389 for __ldap__, 636 for
__ldaps__.) The __ldapi__ scheme is different, because the host part represents the
path of the server socket, and no port can be given.

Upon establishing the connection, the client is anonymous. Servers usually limit access
to some attributes or whole subtrees of the DIT to anonymous users. To overcome this,
the client may need to authenticate, or __bind__, to the directory. Binding is one of
a handful of standardized protocol operations. The usual binding method is called a
_simple bind_, and uses a distinguished name (_bind DN_) and a password as parameters.
The bind DN plays the role of username. The precise form of that DN depends on server
configuration. It should be obvious that sending the password should only be done over
a TLS-protected connection.

Once a client has a connection, it may issue multiple operations to the server. The client
can do this asynchronously, meaning that it does not have to wait for one operation
to complete before issuing another operation. LDAP connections are often long lived.

When the client is finished, it may use the __unbind__ operation or simply drop
the connection. The name "unbind" is slightly misleading, suggesting the opposite
of "bind" while keeping the connection open; this is not the case, since unbinding shuts
down the connection unconditionally.

## 3.2. The Search operation

LDAP is mostly used in read-heavy applications, where data retrieval dominates the usage.
The only way to retrieve one or more entries via LDAP is to use the __search__ operation.
It has a plethora of parameters and options, of which the following four are usually
all it's necessary to provide:

1. The _search base_, the starting point in the DIT for the operation. It must
   lie within a naming context; one exception is the search for the root DSE.

2. The _scope_, which bounds the number of entries that the operation will consider. It
   can have the values _base_, meaning only the entry named as the search base; _one_ (for
   "one level"), which means all entries on the single level immediately below the
   search base, but excluding the base itself; and _sub_ (for "subtree"), containing
   everything at and below the search base.

3. The _filter_, an expression computed for all candidate entries, selecting those for which
   it evaluates to true. An empty filter is syntactically invalid, although some LDAP tools
   automatically substitute it with `(objectClass=*)`, meaning "an entry containing
   a non-empty `objectClass` attribute," that is, all of them.
       
4. The list of _attributes_ to retrieve from the matching entries. If none are specified, only
   the matching entry DNs are returned. The special name `*` means "all attributes," or more
   precisely, all _user_ attributes, since there is an additional set of __operational attributes__
   in each entry, maintained by the directory itself and not modifiable by the user. The set of
   all operational attributes is requested by the special name `+`. Most clients will only
   request the attributes that they really need from the server.

The search operation, like all but two other LDAP operations, returns a result structure, one of
whose elements is a numeric result code. Zero signifies success, while most non-zero values
are errors.

Filters are arguably the most important components of search requests, since they enable finding
and retrieving the relevant entry or a small subset of entries among, potentially, thousands.
Their representation in the request is binary, but a string format is standardized in RFC 4515
and supported by all APIs, command line tools and applications. It's a bit quirky and heavy on
the parentheses, especially if multiple terms and negations are involved, but not too difficult
to understand and write for most day-to-day uses.

Let's suppose that the John Doe entry also has an email address, given by the following LDIF
fragment:

    mail: john.doe@example.com

(The email could be added to the entry as previously specified, since the object class
_inetOrgPerson_ has `mail` among its optional attributes.) If one wanted to search for
a user's entry using the value entred in the login form, the resulting filter might be:

    (uid=john.doe)

However, if the user can enter both the username and the email address, the filter could be
changed to account for both:

    (|(uid=john.doe)(mail=john.doe))

The filter would match an entry which has either `uid` or `mail` with the value "john.doe".
In this case, only the `uid` term would match. If the user entered "john.doe@example.com", the
resulting filter would be:

    (|(uid=john.doe@example.com)(mail=john.doe@example.com))

This filter would match the same entry, but in this case only the `mail` term would evaluate
to true.

The above examples all use __equality__ filters. LDAP also supports other kinds of filters, of
which the most useful are __substrings__, for partial string matches, and __present__, for
matching the entries where an attribute exists irrespective of its value. Filters can be
combined with __or__ (as above), __and__ or __not__.

## 3.3. Other LDAP operations

LDAP provides the full set of operations for maintaining the DIT: adding, modifying and deleting
entries, the analogues of INSERT, UPDATE and DELETE operations on a relational database. A notable
difference is that LDAP operations only work on a single entry. The protocol guarantees that all
modifications of an entry performed in a single operation will be atomic: either all of them
are visible, or none. The guarantee doesn't extend to a series of modifications or other operations
that change the DIT.

The __modify__ operation consists of a sequence of modification requests for a single entry. Each
request can add, delete or replace the values of a single attribute. Logically, the requests must
be performed in the order listed within the operation. Individual requests may temporarily violate
the schema (e.g., if all values of a mandatory attribute are deleted), but the final result must
conform to the schema. Changing or deleting the structural object class or the naming attribute
are not allowed.

For changing the RDN or moving an entry elsewhere in the DIT there is the __modify DN__ operation.
Schema conformance dictates that the naming attribute with the value used in the leaf RDN must
exist in the entry, so renaming an entry to a RDN that is not already present would require two
operations: one to add a new value and one to perform a renaming. To account for this situation,
__modify DN__ will add the new naming attribute and value to the renamed entry automatically,
and will also optionally delete the previous naming attribute-value pair.

## 3.4. Extensions

LDAP operations can be extended in two main ways, using __controls__ and __extended operations__.
Some extensions are standardized, but a lot of them are tied to specific directory service
implementations.

An extended operation is simply another operation, like Bind or Search, that is not part of
the core LDAP specifications. LDAP servers often support at least three extended operations:
__StartTLS__ (mentioned in Section 3.1), __WhoAmI__, and __PasswordModify__.

A control is a named structure, possibly with additional data, attached to an LDAP operation,
which is there to change the operation's behavior in some way. For example, the __Assertion__
control can be used with a Modify operation to indicate that the server should only modify the
entry if the filter attached to the control is true for the entry. An LDAP operation may have
multiple controls attached, with the caveat that the combination must be semantically valid.

Another example is the __SubtreeDelete__ control which is used with the Delete operation to delete
an entire subtree of entries from the DIT.

Each control used has to indicate to the server if the control is "critical" to performing the
operation, or not. If you include a critical control that the server does not support in some way,
the server will fail the entire operation.

Sometimes operation responses contain controls returned from the server, called _response controls_.
A response control is never unsolicited, but tied to the client's control issued in the operation
that elicited the response.
