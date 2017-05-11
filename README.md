# cSslSecurity
DSC Module containing resources used to harden SSL on a Windows Computer and requires the xPSDesiredStateConfiguration DSC resource as a prerequisite. Note that this is an updated version of the PSDesiredStateConfiguration resource that comes with Windows as the original resource contains several bugs.

This contains the following resources:

cSslHardening - This DSC module is used to enable or disable the following SSL components:
    - Ciphers
	- Hashes
	- Key Exchange Algorithms
	- Protocols
	
If you do not have any experience with hardening SSL on a server I recommend reading section 7 of IIS 8.5 hardening document provided by CIS:
https://benchmarks.cisecurity.org/tools2/iis/CIS_Microsoft_IIS_8_Benchmark_v1.5.0.pdf

A good base to start with is the example provided in this resource.