# se_helper
A tool to help manage SE Linux.

This tool is for those who have an understanding of selinux. It is meant to help and it should be used in conjuction with the standard se linux tools like semanage, semodule, 
It will help manage your selinux by showing issues, providing help on policies, activating seusers map ports to selinux, map linux users and groups to selinux groups and users.
It has a menu for easy navigation. An example of the menu looks like this:

Just select the option from the menu below. Example typing "T1" under choice would run T1 found under trouble shooting.

Troubleshooting
===============
   T1.  Find and fix issues (BASIC)<br />
   T2.  Fix all issues automagically (ADVANCED)<br />
   T3.  List current enforced modules<br />
   T4.  Remove an enforced module<br />
   T5.  Build and install selinux module from .te policy file (in custompolicies folder)<br /><br />
Informational
=============
   I1.  Get SELinux running info<br />
   I2.  Set mode to Permissive (temporarily)<br />
   I3.  Set mode to Enforce (temporarily)<br />
   I4.  Get SELInux users<br />
   I5.  Get SELInux logins<br />
   I6.  Get SELInux ports<br /><br />
Users
=====
   U1. Map a local user to a selinux user<br />
   U2. Remap a mapped local user to another selinux user<br />
   U3. Remove the mapping between user and selinux user.<br /><br />
Groups
======
   G1. Map a local/domain group to a selinux user context. (all users in group adopt this context)<br />
   G2. Remap a local/domain group to another selinux user context. (all users in group adopt this context)<br />
   G3. Remove a local/domain group's selinux user context. (affects all users in this group)<br /><br />
Ports
=====
   P1. Map an application port to an SELinux port type for access<br />
   P2. Remove an application port from an SELinux port type<br />

x = Exit<br />
Choice:<br /><br />

