rule phpmailer : webshell {
        meta:
                description = "PHP Mailer injected for mail spam"
                date = "08-02-2022"
                threat_level = "3"
                in_the_wild = true
        strings:
                $s1 = "i could not have a more welcome visitor 64 group of zain bani" fullword ascii
        condition:
                $s1
}

rule ORVXpwShop: webshell {
        meta:
                description = "ORVX.pw Shell <3"
                date = "14-02-2022"
                threat_level = "3"
                in_the_wild = true
        strings:
                $s1 = "Visit our shop orvx.pw" fullword ascii
		$s2 = "shellpassword" fullword ascii
        condition:
                $s1 or $s2
}

rule TrojanBase64Generic : webshell {
        meta:
                description = "Base64 encoded payload"
                date = "08-02-2022"
                threat_level = "3"
                in_the_wild = true
        strings:
                $s1 = "ZXJyb3JfcmVwb3J0aW5nKDApOyBmdW5jdGlvbiBUb3R" fullword ascii
                $s2 = "\"b\".\"a\".\"s\".\"e\".\"6\".\"4\".\"_\".\"d\".\"e\".\"c\".\"o\".\"de\"" fullword ascii
		$s3 = "eval(base64_decode(" fullword ascii
        condition:
                $s1 or $s2 or $s3
}

rule TrojanUrldecode : webshell {
        meta:
                description = "URL encoded payload"
                date = "08-02-2022"
                threat_level = "3"
                in_the_wild = true
        strings:
                $s1 = "eval(rawurldecode(" fullword ascii
        condition:
                $s1
}

rule TrojanPHPGeneric : webshell {
        meta:
                description = "Generic PHP malware"
                date = "14-02-2022"
                threat_level = "3"
                in_the_wild = true
        strings:
                $s1 = "ZXJyb3JfcmVwb3J0aW5nKDApOyBmdW5jdGlvbiBUb3" fullword ascii
                $s2 = "\"b\".\"a\".\"s\".\"e\".\"6\".\"4\".\"_\".\"d\".\"e\".\"c\".\"o\".\"de\"" fullword ascii
		$s3 = "eval(base64_decode(" fullword ascii
		$s4 = "if(md5($_COOKIE[" fullword ascii
        condition:
                $s1 or $s2 or $s3 or $s4
}
