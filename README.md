# ClamAV custom PHP signatures for nimble.

This is a short collection of custom made signatures for common PHP hacks found on WordPress installs.

## Install

You can place these files in `/var/lib/clamav` or whatever your `DatabaseDirectory` says in `/etc/clamav/freshclam.conf`

## Context

We used to run all our sites in WordOps, which (at the time) led to insecure file permissions and LFI exploits. This, in turn created a crazy amount of botnets within our sites, that spread to other, non vulnerable web installs. 

Since we needed to cleanup and migrate each site individually, we created these rules to keep the infection partially at bay automatically such that we wouldn't get blocked by spam or re-hacked by the botnet(s) that were atacking us.

This plus the use of extremely tight rules set on [Shield Security](https://getshieldsecurity.com/) plugin allowed us to migrate all sites with 100% virus cleanup. 

The virus(es) worked by creating numerous backdoor files that would be accessed remotely by another botnet worker, through these they would create even more backdoored PHP files with unsuspecting names. Some of the viruses also created admin users with some `backup_*` username, which meant we could somewhat easily block them once the site was cleaned up by setting up simple rules in the aforementioned plugin.

These were the ules we set, they are simple yet effective:

* 1 month ban on 5 max failed login attempts in a 15min window
* 1 month ban on 5 max 404 pages in a 15min window
