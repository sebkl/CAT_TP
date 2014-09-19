CAT\_TP
======
CAT\_TP is a golang package implementing a CAT\_TP protocol layer for both, client and server side applications. The decoding of CAT\_TP packets from a PCAP stream is also supported. 

##Specification:

This implementation has been built based on the  [ETSI specification](http://www.etsi.org/deliver/etsi_ts/102100_102199/102127/06.13.00_60/ts_102127v061300p.pdf) and makes heavy use of [this libpcap wrapper](https://github.com/miekg/pcap) by [miekg](https://github.com/miekg). Thanks !

## Documentation:
Is available at [at godoc.org](http://godoc.org/github.com/sebkl/CAT_TP).

## TODO

 * Implement example.
 * Implement sending of extenden Acknowledgements.
 * Implement CAT\_TP port allocation. Currently source and destination ports must be specified explicitly.
 * Add callback hooks for connection states.
 * Implement tcpdump like command line util


