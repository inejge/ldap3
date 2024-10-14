# LDAP server for examples

This directory contains setup scripts and data files for creating
an OpenLDAP server against which example programs can be run. The scripts
expect that you have a recent-ish OpenLDAP installation on your system;
you should also make sure that `slapadd` and `slapd` are in your `$PATH`.

The scripts were originally tested on CentOS 7 and Ubuntu 16.04. Later
Ubuntu releases should behave the same. Following the lead of its parent,
RHEL, CentOS 8 no longer includes the OpenLDAP server. After the demise of
CentOS 8, successors like AlmaLinux and Rocky Linux have incorporated OpenLDAP
in the additional repositories, but the easiest route is to use the packages
provided by the [LTB project](https://ltb-project.org/download.html),
which also has the latest OpenLDAP for Debian and Ubuntu.

CentOS 7 is EOL, as is OpenLDAP 2.4.x. Use at least version 8 of RHEL and its
derivatives, and OpenLDAP 2.5 or later.

* On Ubuntu, install `slapd` and `ldap-utils`.

* On RHEL/Alma/Rocky, configure the [LTB yum repository](https://www.ltb-project.org/documentation/openldap-rpm.html)
  and install `openldap-ltb`.

* Whatever the distro, install `make`.

This setup shouldn't be used for anything serious: in the interest of
uniformity, it uses Debian-specific parameters for the config database
which just happen to work elsewhere, but would almost certainly cause
problems for anything more complex.

All scripts should be run from this directory.

* To start from a clean slate, run `make clean`.

* To create the example database and import the data, run `make db`.

* To start the database, run `./startdb.sh`. Additional arguments will be
  passed to `slapd`.

* To stop the database, run `./stopdb.sh`.

The database server will listen on __localhost:2389__ (ldap), __localhost:2636__ (ldaps),
and a Unix domain socket __ldapi__ in the current directory. Setting `$LDAP3_EXAMPLE_SERVER`
to a hostname or IP address will use that instead of __localhost__.

Examples are run by invoking `cargo run --quiet --example`_`name`_.
For the file `examples/bind_sync.rs`, that would be
`cargo run --quiet --example bind_sync`.
