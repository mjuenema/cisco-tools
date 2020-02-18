# ciscoaclparse

**THIS IS CURRENTLY A DESIGN DOCUMENT AND NOT YET IMPLEMENTED**

*ciscoaclparse* is a library for parsing the output of the Cisco ``show access-list`` command into a list of Python
objects. The module provides a single ``parse()`` function that accepts a file-like object. The return value is a list of 
``ciscoaclparse.Rule`` instances (see below for details).

Example:

```python
import ciscoaclparse

with open('show-access-list.txt', 'rt') as fp:
    rules = ciscoaclparse.parse(fp)
    
assert isinstance(rules, list)
assert isinstance(rules[0], ciscoaclparse.Rule)
```

One possible use case is to filter the list of rules.

```python
http_rules = [rule for rule in rules where rule.destination_port == 80]
```

## Structure of Cisco Access Control List entries

While there are differences between the different Cisco platforms (IOS, IOS-XR, ASA, ...) and software releases, the general
structure of an Access Control List entry is similar between all of them. Here are some examples.

**ASA xx.x Firewall**
```
access-list MyAcl line 8 extended permit tcp host 10.1.1.1 host 10.2.2.2 eq ssh (hitcnt=363) 0xa0199780
            ^^^^^ ^^^^^^ ^^^^^^^^ ^^^    ^^^ ^^^^^^^^^     ^^^^^^^^^^^^^ ^^^^^^         ^^^  ^^^^^^^^^^
            Name   Line# Type     Action Pro Source        Destination   Port     Hit count  Hash      
```

**IOS 12.x**
```
access-list
```

**IOS 15.x**
```
access-list
```

**IOS-XR 6.x**
```
access-list
```

## The ``Rule`` class

The ``Rule`` class represents a parsed Access Control List entry with attributes for each of the individual elements. All
attributes are instances of custom Python classes which are explained later in this document. Most of these classes 
behave like normal Python strings and integers but some are more intricate. Attributes that are not found in the  
input will have a value of ``None``.

* ``name`` is the name of the Access Control List.
* ``line`` is the number of the ACL entry as an integer.
* ``type`` is either "standard" or "extended".
* ``action`` is either "permit" or "deny".
* ``protocol`` is one of "icmp", "tcp", "udp" or "any".
* ``source`` and ``destination`` are instances of [netaddr.IPSet](https://netaddr.readthedocs.io/en/latest/api.html#ip-sets).
* ``source_port`` adn ``destination_port`` are instance of ``Port`` which is like an integer but also supports names
  (e,g, "telnet", "ssh") and port ranges. 
* ``hits`` is the number of times this rule matched.
* ``hash`` is specific to Cisco ASA Firewalls.
* The ``remark`` holds the text that follows a "remark" statement in the input. It is available in every rule that the 
  remark referred to. 

## String-like types

The ``name``, ``type``, ``action``, ``protocol`` and ``hash`` attributes are sub-classes of Python strings and inherit 
all their features. The only reason for not using the actual Python string type is that it allows for the future addition
of custom methods if necessary.

## Integer-like types

The ``line`` and ``hits`` attributes behave like Python integers. Like with string-like types they allow for
the future addition of custom methods if necessary.

## The ``netaddr.IPSet`` type

The [netaddr.IPSet](https://netaddr.readthedocs.io/en/latest/api.html#ip-sets) is used for the ``source`` and
``destination`` attributes. It conveniently accomodates all the different IP address and network syntaxes 
Cisco Access Control Lists may contain.

TODO: Explain operations.

Check [netaddr.IPSet](https://netaddr.readthedocs.io/en/latest/api.html#ip-sets) for the full set of supported operators.

## The ``Port`` type

The ``source_port`` and ``destination_port`` attributes are based on Python integers but support text values 
("http", "ssh", ...) and port ranges. This allows for a lot of flexibility if one wants to compare values.

```python
# Integer comparison
assert 80 == rule.destination_port

# Text comparison
assert "http" == destination_rule.port

# Check whether a port is contained in a range of ports
assert "http" in destination_rule.port
```

## Aliases

For convenience some attributes can also be referred to by an alias.

| Attribute | Aliases |
|-----------|---------|
| ``protocol`` | ``proto`` |
| ``source`` | ``src`` |
| ``destination`` | ``dest``, ``dst`` |
| ``source_port`` | ``sport`` |
| ``destination_port`` | ``dport``, ``port`` |
| ``hits`` | ``hitcnt`` |
| ``remark`` | ``comment`` |





Markus Juenemann, 18-Feb-2020
