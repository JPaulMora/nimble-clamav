# Nimble ClamAV Signatures

Custom ClamAV signatures for detecting PHP malware commonly found in compromised WordPress installations.

## What's Included

- **customsig.ndb** - Hash-based signatures for known malware variants
- **customsig.yara** - Pattern-based YARA rules for detecting obfuscated code patterns

## What This Detects

Based on real-world infections, these signatures detect:

- **PHP Mailers** - Spam mailer scripts (PHPMailer injections, LeafMailer)
- **Web Shells** - Backdoor shells (ORVX.pw, WSO variants, anonymousfox, Dasha)
- **Obfuscated Malware** - Base64, URL encoded, and string concatenation tricks
- **Botnet Scripts** - Auto-spreading malware and crawler bots
- **Generic Patterns** - Common malware signatures (eval chains, cookie-based auth, ICO file injections)

## Installation

1. Copy files to your ClamAV database directory:
   ```bash
   sudo cp customsig.ndb customsig.yara /var/lib/clamav/
   ```

2. Set proper permissions:
   ```bash
   sudo chown clamav:clamav /var/lib/clamav/customsig.*
   sudo chmod 644 /var/lib/clamav/customsig.*
   ```

3. Reload ClamAV signatures:
   ```bash
   sudo systemctl restart clamav-daemon
   # or if using freshclam
   sudo freshclam
   ```

4. Verify signatures loaded:
   ```bash
   sigtool --list-sigs | grep -E "customsig|php\."
   ```

## Usage

Scan a WordPress installation:
```bash
clamscan -r /var/www/html/wordpress
```

Scan with detailed output and remove infected files:
```bash
clamscan -r -i --remove /var/www/html
```

Scan and move infected files to quarantine:
```bash
clamscan -r --move=/quarantine /var/www/html
```

## Creating New Signatures

### Hash-Based Signatures (.ndb)

For exact file matching, create MD5 hash signatures:

1. Generate hex signature from a malware file:
   ```bash
   sigtool --hex-dump malware.php > malware.hex
   ```

2. Add entry to `customsig.ndb` with format:
   ```
   SignatureName:TargetType:Offset:HexSignature
   ```

   Example:
   ```
   php.Trojan.MyMalware:0:*:3c3f706870206576616c286261736536345f6465636f646528
   ```

   - `SignatureName` - Unique name (convention: `php.Type.Name`)
   - `TargetType` - File type (0 = any, 1 = PE, etc.)
   - `Offset` - Where to look (* = anywhere)
   - `HexSignature` - Hex-encoded pattern to match

### Pattern-Based Signatures (.yara)

For flexible pattern matching, create YARA rules:

```yara
rule MalwareName : webshell {
    meta:
        description = "Description of what this detects"
        date = "DD-MM-YYYY"
        threat_level = "3"
        in_the_wild = true
    strings:
        $s1 = "unique_string_1" fullword ascii
        $s2 = "unique_string_2" fullword ascii
        $s3 = { 6d 61 6c 77 61 72 65 } // hex pattern
    condition:
        2 of ($s1,$s2,$s3)
}
```

Tips for creating effective signatures:
- Use unique strings unlikely to appear in legitimate code
- Combine multiple weak indicators with logical conditions
- Test against clean files to avoid false positives
- Use `fullword` to match complete words only
- Use hex patterns for binary data or obfuscated strings

### Testing New Signatures

Test before deploying:
```bash
clamscan -d customsig.ndb -d customsig.yara suspicious_file.php
```

## Background

We used to run all our sites in WordOps, which (at the time) led to insecure file permissions and LFI exploits. This, in turn, created a massive amount of botnets within our sites that spread to other, non-vulnerable web installs.

Since we needed to cleanup and migrate each site individually, we created these rules to keep the infection partially at bay automatically such that we wouldn't get blocked by spam or re-hacked by the botnet(s) that were attacking us.

This plus the use of extremely tight rules set on [Shield Security](https://getshieldsecurity.com/) plugin allowed us to migrate all sites with 100% virus cleanup.

The virus(es) worked by creating numerous backdoor files that would be accessed remotely by another botnet worker, through these they would create even more backdoored PHP files with unsuspecting names. Some of the viruses also created admin users with some `backup_*` username, which meant we could somewhat easily block them once the site was cleaned up by setting up simple rules in the aforementioned plugin.

### Shield Security Rules

These were the rules we set, they are simple yet effective:

* 1 month ban on 5 max failed login attempts in a 15min window
* 1 month ban on 5 max 404 pages in a 15min window

## Disclaimer

These signatures may produce false positives. Always review detections before deleting files. Test in a non-production environment first.

## Contributing

Found new malware patterns? Submit a PR or open an issue with:
- Sample file (sanitized/encrypted if possible)
- Description of the malware behavior
- Proposed signature

## References

- [ClamAV Signature Documentation](https://docs.clamav.net/manual/Signatures.html)
- [YARA Documentation](https://yara.readthedocs.io/)
- [sigtool Manual](https://docs.clamav.net/manual/Usage/SignatureManagement.html)

## License

See [LICENSE](LICENSE) file for details.