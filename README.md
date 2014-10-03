# Cisco ACL Analyzer

This is repository for project hosted on [acl.frenzy.cz](http://acl.frenzy.cz/).

## Why you want to use it?

This web application allows you to check, which rule from your Cisco ACL affects your imaginary packet.

I use it when I have ACL with a lot of rules and trying to discover which rule permit or deny my connection trough firewall.

## How to use it?

Preffered workflow is:

1. Create imaginary packet:
    1. Choose connection type from selectbox - TCP, UDP, ICMP
    2. Enter source IP address
    3. Enter source port or leave this field blank for generate random source port
    4. Enter destination IP address
    5. Enter destination packet or leave this field blank for generate random destination port
2. Paste your ACL to textbox
    - Copy it from CLI (*show ip access-list <my-access-list-name>*)
    - Copy it from configuration file (*ip access-list extended <my-access-list-name>*)
3. Click to Analyze

## What is result?

The result is table with same rules as in your ACL but compared to your packet. Green rules permits packet and red rules denies packet. Any other rules with no special color has some mismatches between packet and rule definition and this mismatches is explained in last table column.

## Project status

This project is in active development, but only for my needs.

If you want some more features, issues or pull-requests are welcome.

## Author

Lumír Balhar, [frenzy.madness@gmail.com](mailto:frenzy.madness@gmail.com), [@lumirbalhar](https://twitter.com/lumirbalhar)

## License

GPL
