# Timgad

Timgad is a Linux Security Module that collects per process and
system-wide security protections that are not handled by the core kernel
itself.

This is selectable at build-time with CONFIG_SECURITY_TIMGAD, and can be
controlled at run-time through sysctls in /proc/sys/kernel/timgad:
or prctl() interface.

Link: http://www.openwall.com/lists/kernel-hardening/2017/02/02/21

- module_restrict

==============================================================

Linux containers need robust settings to control if modules are allowed to
be loaded or unloaded globally or per process/container policy.

This adds global sysctl settings to indicate if the modules are allowed
to be loaded or unloaded, at same time it also supports a
per-process/container settings based on prctl(2) interface. The prctl(2)
settings are inherited by children created by fork(2) and clone(2), and
preserved across execve(2).


*) The per-process prctl() settings are:
   prctl(PR_TIMGAD_OPTS, PR_TIGMAD_SET_MOD_RESTRICT, value, 0, 0)

   Where value means:

0 - Classic module load and unload permissions, nothing changes.

1 - The current process must have CAP_SYS_MODULE to be able to load and
    unload modules. CAP_NET_ADMIN should allow the current process to
    load and unload only netdev aliased modules.

2 - Current process can not loaded nor unloaded modules.


*) The sysctl settings (writable only with CAP_SYS_MODULE) are:
   /proc/sys/kernel/timgad/module_restrict

0 - Classic module load and unload permissions, nothing changes.

1 - Only processes with CAP_SYS_MODULE should be able to load and
    unload modules. Processes with CAP_NET_ADMIN should be able to
    load and unload only netdev aliased modules.

2 - Modules can not be loaded nor unloaded. Once set, this sysctl value
    cannot be changed.

Rules:
First the prctl() settings are checked, if the access is not denied
then the global sysctl settings are checked.


The original idea and inspiration is from grsecurity
'GRKERNSEC_MODHARDEN'

==============================================================
