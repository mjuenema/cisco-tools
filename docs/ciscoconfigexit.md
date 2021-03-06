# ciscoconfexit

**ciscoconfexit** inserts ``exit`` statements into a Cisco configuration so one can copy-and-paste it.

There are currently two open issues #1 and #2.

Example:

```
! input.cfg
interface FastEthernet 1/1
  description Internet
  ip address 192.168.1.1 255.255.255.0
!
interface FastEthernet 1/1
  description LAN
  ip address 172.16.1.1 255.255.255.0
!
```

Running **ciscoconfexit** will insert ``exit`` statements where required.

```
$ ciscoconfexit input.cfg > output.cfg

$ cat output.cfg
! output.cfg
interface FastEthernet 1/1
  description Internet
  ip address 192.168.1.1 255.255.255.0
  exit
!
interface FastEthernet 1/1
  description LAN
  ip address 172.16.1.1 255.255.255.0
  exit
!
```

