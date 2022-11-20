use crate::port::Port;
use std::cmp::min;

/// Defines a tcp port with service name & number
#[derive(Debug)]
struct PortDefinition<'a> {
    service: &'a str,
    number: u16,
}

impl From<&PortDefinition<'_>> for Port {
    fn from(def: &PortDefinition) -> Port {
        Port {
            service: def.service.to_owned(),
            number: def.number,
            is_open: None,
        }
    }
}

impl From<PortDefinition<'_>> for Port {
    fn from(def: PortDefinition) -> Port {
        Port {
            service: def.service.to_owned(),
            number: def.number,
            is_open: None,
        }
    }
}

/// Get n most common ports with a maximum of 5000 ports
pub fn get_common_ports(n: usize) -> Vec<Port> {
    let mut ports = Vec::new();
    let n = min(n, 5000);
    for i in 0..n {
        let port = (&MOST_COMMON_PORTS[i]).into();
        ports.push(port);
    }
    ports
}

/// The 5000 most common ports
///
/// Source: `awk '$2~/tcp$/' /c/Program\ Files\ \(x86\)/Nmap/nmap-services | sort -r -k3 | head -n 5000`
const MOST_COMMON_PORTS: &'static [PortDefinition] = &[
    PortDefinition {
        service: "http",
        number: 80,
    },
    PortDefinition {
        service: "telnet",
        number: 23,
    },
    PortDefinition {
        service: "https",
        number: 443,
    },
    PortDefinition {
        service: "ftp",
        number: 21,
    },
    PortDefinition {
        service: "ssh",
        number: 22,
    },
    PortDefinition {
        service: "smtp",
        number: 25,
    },
    PortDefinition {
        service: "ms-wbt-server",
        number: 3389,
    },
    PortDefinition {
        service: "pop3",
        number: 110,
    },
    PortDefinition {
        service: "microsoft-ds",
        number: 445,
    },
    PortDefinition {
        service: "netbios-ssn",
        number: 139,
    },
    PortDefinition {
        service: "imap",
        number: 143,
    },
    PortDefinition {
        service: "domain",
        number: 53,
    },
    PortDefinition {
        service: "msrpc",
        number: 135,
    },
    PortDefinition {
        service: "mysql",
        number: 3306,
    },
    PortDefinition {
        service: "http-proxy",
        number: 8080,
    },
    PortDefinition {
        service: "pptp",
        number: 1723,
    },
    PortDefinition {
        service: "rpcbind",
        number: 111,
    },
    PortDefinition {
        service: "pop3s",
        number: 995,
    },
    PortDefinition {
        service: "imaps",
        number: 993,
    },
    PortDefinition {
        service: "vnc",
        number: 5900,
    },
    PortDefinition {
        service: "NFS-or-IIS",
        number: 1025,
    },
    PortDefinition {
        service: "submission",
        number: 587,
    },
    PortDefinition {
        service: "sun-answerbook",
        number: 8888,
    },
    PortDefinition {
        service: "smux",
        number: 199,
    },
    PortDefinition {
        service: "h323q931",
        number: 1720,
    },
    PortDefinition {
        service: "smtps",
        number: 465,
    },
    PortDefinition {
        service: "afp",
        number: 548,
    },
    PortDefinition {
        service: "ident",
        number: 113,
    },
    PortDefinition {
        service: "hosts2-ns",
        number: 81,
    },
    PortDefinition {
        service: "X11:1",
        number: 6001,
    },
    PortDefinition {
        service: "snet-sensor-mgmt",
        number: 10000,
    },
    PortDefinition {
        service: "shell",
        number: 514,
    },
    PortDefinition {
        service: "sip",
        number: 5060,
    },
    PortDefinition {
        service: "bgp",
        number: 179,
    },
    PortDefinition {
        service: "LSA-or-nterm",
        number: 1026,
    },
    PortDefinition {
        service: "cisco-sccp",
        number: 2000,
    },
    PortDefinition {
        service: "https-alt",
        number: 8443,
    },
    PortDefinition {
        service: "http-alt",
        number: 8000,
    },
    PortDefinition {
        service: "filenet-tms",
        number: 32768,
    },
    PortDefinition {
        service: "rtsp",
        number: 554,
    },
    PortDefinition {
        service: "rsftp",
        number: 26,
    },
    PortDefinition {
        service: "ms-sql-s",
        number: 1433,
    },
    PortDefinition {
        service: "unknown",
        number: 49152,
    },
    PortDefinition {
        service: "dc",
        number: 2001,
    },
    PortDefinition {
        service: "printer",
        number: 515,
    },
    PortDefinition {
        service: "http",
        number: 8008,
    },
    PortDefinition {
        service: "unknown",
        number: 49154,
    },
    PortDefinition {
        service: "IIS",
        number: 1027,
    },
    PortDefinition {
        service: "nrpe",
        number: 5666,
    },
    PortDefinition {
        service: "ldp",
        number: 646,
    },
    PortDefinition {
        service: "upnp",
        number: 5000,
    },
    PortDefinition {
        service: "pcanywheredata",
        number: 5631,
    },
    PortDefinition {
        service: "ipp",
        number: 631,
    },
    PortDefinition {
        service: "unknown",
        number: 49153,
    },
    PortDefinition {
        service: "blackice-icecap",
        number: 8081,
    },
    PortDefinition {
        service: "nfs",
        number: 2049,
    },
    PortDefinition {
        service: "kerberos-sec",
        number: 88,
    },
    PortDefinition {
        service: "finger",
        number: 79,
    },
    PortDefinition {
        service: "vnc-http",
        number: 5800,
    },
    PortDefinition {
        service: "pop3pw",
        number: 106,
    },
    PortDefinition {
        service: "ccproxy-ftp",
        number: 2121,
    },
    PortDefinition {
        service: "nfsd-status",
        number: 1110,
    },
    PortDefinition {
        service: "unknown",
        number: 49155,
    },
    PortDefinition {
        service: "X11",
        number: 6000,
    },
    PortDefinition {
        service: "login",
        number: 513,
    },
    PortDefinition {
        service: "ftps",
        number: 990,
    },
    PortDefinition {
        service: "wsdapi",
        number: 5357,
    },
    PortDefinition {
        service: "svrloc",
        number: 427,
    },
    PortDefinition {
        service: "unknown",
        number: 49156,
    },
    PortDefinition {
        service: "klogin",
        number: 543,
    },
    PortDefinition {
        service: "kshell",
        number: 544,
    },
    PortDefinition {
        service: "admdog",
        number: 5101,
    },
    PortDefinition {
        service: "news",
        number: 144,
    },
    PortDefinition {
        service: "echo",
        number: 7,
    },
    PortDefinition {
        service: "ldap",
        number: 389,
    },
    PortDefinition {
        service: "ajp13",
        number: 8009,
    },
    PortDefinition {
        service: "squid-http",
        number: 3128,
    },
    PortDefinition {
        service: "snpp",
        number: 444,
    },
    PortDefinition {
        service: "abyss",
        number: 9999,
    },
    PortDefinition {
        service: "airport-admin",
        number: 5009,
    },
    PortDefinition {
        service: "realserver",
        number: 7070,
    },
    PortDefinition {
        service: "aol",
        number: 5190,
    },
    PortDefinition {
        service: "ppp",
        number: 3000,
    },
    PortDefinition {
        service: "postgresql",
        number: 5432,
    },
    PortDefinition {
        service: "upnp",
        number: 1900,
    },
    PortDefinition {
        service: "mapper-ws_ethd",
        number: 3986,
    },
    PortDefinition {
        service: "daytime",
        number: 13,
    },
    PortDefinition {
        service: "ms-lsa",
        number: 1029,
    },
    PortDefinition {
        service: "discard",
        number: 9,
    },
    PortDefinition {
        service: "ida-agent",
        number: 5051,
    },
    PortDefinition {
        service: "unknown",
        number: 6646,
    },
    PortDefinition {
        service: "unknown",
        number: 49157,
    },
    PortDefinition {
        service: "unknown",
        number: 1028,
    },
    PortDefinition {
        service: "rsync",
        number: 873,
    },
    PortDefinition {
        service: "wms",
        number: 1755,
    },
    PortDefinition {
        service: "pn-requester",
        number: 2717,
    },
    PortDefinition {
        service: "radmin",
        number: 4899,
    },
    PortDefinition {
        service: "jetdirect",
        number: 9100,
    },
    PortDefinition {
        service: "nntp",
        number: 119,
    },
    PortDefinition {
        service: "time",
        number: 37,
    },
    PortDefinition {
        service: "cadlock",
        number: 1000,
    },
    PortDefinition {
        service: "nessus",
        number: 3001,
    },
    PortDefinition {
        service: "commplex-link",
        number: 5001,
    },
    PortDefinition {
        service: "xfer",
        number: 82,
    },
    PortDefinition {
        service: "rxapi",
        number: 10010,
    },
    PortDefinition {
        service: "iad1",
        number: 1030,
    },
    PortDefinition {
        service: "zeus-admin",
        number: 9090,
    },
    PortDefinition {
        service: "msmq-mgmt",
        number: 2107,
    },
    PortDefinition {
        service: "kdm",
        number: 1024,
    },
    PortDefinition {
        service: "zephyr-clt",
        number: 2103,
    },
    PortDefinition {
        service: "X11:4",
        number: 6004,
    },
    PortDefinition {
        service: "msmq",
        number: 1801,
    },
    PortDefinition {
        service: "mmcc",
        number: 5050,
    },
    PortDefinition {
        service: "chargen",
        number: 19,
    },
    PortDefinition {
        service: "unknown",
        number: 8031,
    },
    PortDefinition {
        service: "danf-ak2",
        number: 1041,
    },
    PortDefinition {
        service: "unknown",
        number: 255,
    },
    PortDefinition {
        service: "td-postman",
        number: 1049,
    },
    PortDefinition {
        service: "neod2",
        number: 1048,
    },
    PortDefinition {
        service: "symantec-av",
        number: 2967,
    },
    PortDefinition {
        service: "remote-as",
        number: 1053,
    },
    PortDefinition {
        service: "adobeserver-3",
        number: 3703,
    },
    PortDefinition {
        service: "vfo",
        number: 1056,
    },
    PortDefinition {
        service: "syscomlan",
        number: 1065,
    },
    PortDefinition {
        service: "jstel",
        number: 1064,
    },
    PortDefinition {
        service: "brvread",
        number: 1054,
    },
    PortDefinition {
        service: "qotd",
        number: 17,
    },
    PortDefinition {
        service: "ccproxy-http",
        number: 808,
    },
    PortDefinition {
        service: "rendezvous",
        number: 3689,
    },
    PortDefinition {
        service: "iad2",
        number: 1031,
    },
    PortDefinition {
        service: "dcutility",
        number: 1044,
    },
    PortDefinition {
        service: "bsquare-voip",
        number: 1071,
    },
    PortDefinition {
        service: "vnc-1",
        number: 5901,
    },
    PortDefinition {
        service: "jetdirect",
        number: 9102,
    },
    PortDefinition {
        service: "newacct",
        number: 100,
    },
    PortDefinition {
        service: "xmpp",
        number: 8010,
    },
    PortDefinition {
        service: "icslap",
        number: 2869,
    },
    PortDefinition {
        service: "sbl",
        number: 1039,
    },
    PortDefinition {
        service: "barracuda-bbs",
        number: 5120,
    },
    PortDefinition {
        service: "newoak",
        number: 4001,
    },
    PortDefinition {
        service: "cslistener",
        number: 9000,
    },
    PortDefinition {
        service: "eklogin",
        number: 2105,
    },
    PortDefinition {
        service: "ldapssl",
        number: 636,
    },
    PortDefinition {
        service: "mtqp",
        number: 1038,
    },
    PortDefinition {
        service: "zebra",
        number: 2601,
    },
    PortDefinition {
        service: "tcpmux",
        number: 1,
    },
    PortDefinition {
        service: "afs3-fileserver",
        number: 7000,
    },
    PortDefinition {
        service: "fpo-fns",
        number: 1066,
    },
    PortDefinition {
        service: "cognex-insight",
        number: 1069,
    },
    PortDefinition {
        service: "apple-xsrvr-admin",
        number: 625,
    },
    PortDefinition {
        service: "asip-webadmin",
        number: 311,
    },
    PortDefinition {
        service: "http-mgmt",
        number: 280,
    },
    PortDefinition {
        service: "unknown",
        number: 254,
    },
    PortDefinition {
        service: "remoteanything",
        number: 4000,
    },
    PortDefinition {
        service: "landesk-rc",
        number: 1761,
    },
    PortDefinition {
        service: "filemaker",
        number: 5003,
    },
    PortDefinition {
        service: "globe",
        number: 2002,
    },
    PortDefinition {
        service: "deslogin",
        number: 2005,
    },
    PortDefinition {
        service: "x25-svc-port",
        number: 1998,
    },
    PortDefinition {
        service: "iad3",
        number: 1032,
    },
    PortDefinition {
        service: "java-or-OTGfileshare",
        number: 1050,
    },
    PortDefinition {
        service: "dtspc",
        number: 6112,
    },
    PortDefinition {
        service: "svn",
        number: 3690,
    },
    PortDefinition {
        service: "oracle",
        number: 1521,
    },
    PortDefinition {
        service: "apc-agent",
        number: 2161,
    },
    PortDefinition {
        service: "X11:2",
        number: 6002,
    },
    PortDefinition {
        service: "socks",
        number: 1080,
    },
    PortDefinition {
        service: "cvspserver",
        number: 2401,
    },
    PortDefinition {
        service: "lockd",
        number: 4045,
    },
    PortDefinition {
        service: "iss-realsecure",
        number: 902,
    },
    PortDefinition {
        service: "nsrexecd",
        number: 7937,
    },
    PortDefinition {
        service: "qsc",
        number: 787,
    },
    PortDefinition {
        service: "nim",
        number: 1058,
    },
    PortDefinition {
        service: "ms-olap4",
        number: 2383,
    },
    PortDefinition {
        service: "sometimes-rpc5",
        number: 32771,
    },
    PortDefinition {
        service: "netinfo",
        number: 1033,
    },
    PortDefinition {
        service: "netsaint",
        number: 1040,
    },
    PortDefinition {
        service: "nimreg",
        number: 1059,
    },
    PortDefinition {
        service: "ibm-db2",
        number: 50000,
    },
    PortDefinition {
        service: "freeciv",
        number: 5555,
    },
    PortDefinition {
        service: "scp-config",
        number: 10001,
    },
    PortDefinition {
        service: "citrix-ica",
        number: 1494,
    },
    PortDefinition {
        service: "http-rpc-epmap",
        number: 593,
    },
    PortDefinition {
        service: "compaqdiag",
        number: 2301,
    },
    PortDefinition {
        service: "compressnet",
        number: 3,
    },
    PortDefinition {
        service: "globalcatLDAP",
        number: 3268,
    },
    PortDefinition {
        service: "lgtomapper",
        number: 7938,
    },
    PortDefinition {
        service: "hotline",
        number: 1234,
    },
    PortDefinition {
        service: "exp2",
        number: 1022,
    },
    PortDefinition {
        service: "warmspotMgmt",
        number: 1074,
    },
    PortDefinition {
        service: "teradataordbms",
        number: 8002,
    },
    PortDefinition {
        service: "nsstp",
        number: 1036,
    },
    PortDefinition {
        service: "multidropper",
        number: 1035,
    },
    PortDefinition {
        service: "tor-orport",
        number: 9001,
    },
    PortDefinition {
        service: "ams",
        number: 1037,
    },
    PortDefinition {
        service: "kpasswd5",
        number: 464,
    },
    PortDefinition {
        service: "retrospect",
        number: 497,
    },
    PortDefinition {
        service: "rtmp",
        number: 1935,
    },
    PortDefinition {
        service: "irc",
        number: 6666,
    },
    PortDefinition {
        service: "finger",
        number: 2003,
    },
    PortDefinition {
        service: "mythtv",
        number: 6543,
    },
    PortDefinition {
        service: "lotusnotes",
        number: 1352,
    },
    PortDefinition {
        service: "priv-mail",
        number: 24,
    },
    PortDefinition {
        service: "globalcatLDAPssl",
        number: 3269,
    },
    PortDefinition {
        service: "lmsocialserver",
        number: 1111,
    },
    PortDefinition {
        service: "timbuktu",
        number: 407,
    },
    PortDefinition {
        service: "isakmp",
        number: 500,
    },
    PortDefinition {
        service: "ftp-data",
        number: 20,
    },
    PortDefinition {
        service: "invokator",
        number: 2006,
    },
    PortDefinition {
        service: "iscsi",
        number: 3260,
    },
    PortDefinition {
        service: "hydap",
        number: 15000,
    },
    PortDefinition {
        service: "aeroflight-ads",
        number: 1218,
    },
    PortDefinition {
        service: "zincite-a",
        number: 1034,
    },
    PortDefinition {
        service: "krb524",
        number: 4444,
    },
    PortDefinition {
        service: "bgmp",
        number: 264,
    },
    PortDefinition {
        service: "mailbox",
        number: 2004,
    },
    PortDefinition {
        service: "dsp",
        number: 33,
    },
    PortDefinition {
        service: "afrog",
        number: 1042,
    },
    PortDefinition {
        service: "caerpc",
        number: 42510,
    },
    PortDefinition {
        service: "garcon",
        number: 999,
    },
    PortDefinition {
        service: "powerchute",
        number: 3052,
    },
    PortDefinition {
        service: "netvenuechat",
        number: 1023,
    },
    PortDefinition {
        service: "instl_bootc",
        number: 1068,
    },
    PortDefinition {
        service: "rsh-spx",
        number: 222,
    },
    PortDefinition {
        service: "font-service",
        number: 7100,
    },
    PortDefinition {
        service: "accessbuilder",
        number: 888,
    },
    PortDefinition {
        service: "snews",
        number: 563,
    },
    PortDefinition {
        service: "fj-hdnet",
        number: 1717,
    },
    PortDefinition {
        service: "conf",
        number: 2008,
    },
    PortDefinition {
        service: "telnets",
        number: 992,
    },
    PortDefinition {
        service: "sometimes-rpc3",
        number: 32770,
    },
    PortDefinition {
        service: "sometimes-rpc7",
        number: 32772,
    },
    PortDefinition {
        service: "afs3-callback",
        number: 7001,
    },
    PortDefinition {
        service: "blackice-alerts",
        number: 8082,
    },
    PortDefinition {
        service: "dectalk",
        number: 2007,
    },
    PortDefinition {
        service: "sdadmind",
        number: 5550,
    },
    PortDefinition {
        service: "news",
        number: 2009,
    },
    PortDefinition {
        service: "vnc-http-1",
        number: 5801,
    },
    PortDefinition {
        service: "boinc",
        number: 1043,
    },
    PortDefinition {
        service: "exec",
        number: 512,
    },
    PortDefinition {
        service: "sms-rcinfo",
        number: 2701,
    },
    PortDefinition {
        service: "doceri-ctl",
        number: 7019,
    },
    PortDefinition {
        service: "unknown",
        number: 50001,
    },
    PortDefinition {
        service: "mps-raft",
        number: 1700,
    },
    PortDefinition {
        service: "edonkey",
        number: 4662,
    },
    PortDefinition {
        service: "dlsrpn",
        number: 2065,
    },
    PortDefinition {
        service: "search",
        number: 2010,
    },
    PortDefinition {
        service: "nameserver",
        number: 42,
    },
    PortDefinition {
        service: "man",
        number: 9535,
    },
    PortDefinition {
        service: "ripd",
        number: 2602,
    },
    PortDefinition {
        service: "dec-notes",
        number: 3333,
    },
    PortDefinition {
        service: "snmp",
        number: 161,
    },
    PortDefinition {
        service: "admd",
        number: 5100,
    },
    PortDefinition {
        service: "rfe",
        number: 5002,
    },
    PortDefinition {
        service: "ospfd",
        number: 2604,
    },
    PortDefinition {
        service: "mlchat-proxy",
        number: 4002,
    },
    PortDefinition {
        service: "X11:59",
        number: 6059,
    },
    PortDefinition {
        service: "neod1",
        number: 1047,
    },
    PortDefinition {
        service: "sophos",
        number: 8192,
    },
    PortDefinition {
        service: "sophos",
        number: 8193,
    },
    PortDefinition {
        service: "sms-xfer",
        number: 2702,
    },
    PortDefinition {
        service: "ibm-db2-admin",
        number: 6789,
    },
    PortDefinition {
        service: "pds",
        number: 9595,
    },
    PortDefinition {
        service: "optima-vnet",
        number: 1051,
    },
    PortDefinition {
        service: "msgsys",
        number: 9594,
    },
    PortDefinition {
        service: "cba8",
        number: 9593,
    },
    PortDefinition {
        service: "amt-soap-https",
        number: 16993,
    },
    PortDefinition {
        service: "amt-soap-http",
        number: 16992,
    },
    PortDefinition {
        service: "hp-status",
        number: 5226,
    },
    PortDefinition {
        service: "hp-server",
        number: 5225,
    },
    PortDefinition {
        service: "filenet-rpc",
        number: 32769,
    },
    PortDefinition {
        service: "ddt",
        number: 1052,
    },
    PortDefinition {
        service: "sophos",
        number: 8194,
    },
    PortDefinition {
        service: "ansyslmd",
        number: 1055,
    },
    PortDefinition {
        service: "netassistant",
        number: 3283,
    },
    PortDefinition {
        service: "veracity",
        number: 1062,
    },
    PortDefinition {
        service: "unknown",
        number: 9415,
    },
    PortDefinition {
        service: "unknown",
        number: 8701,
    },
    PortDefinition {
        service: "unknown",
        number: 8652,
    },
    PortDefinition {
        service: "unknown",
        number: 8651,
    },
    PortDefinition {
        service: "unknown",
        number: 8089,
    },
    PortDefinition {
        service: "unknown",
        number: 65389,
    },
    PortDefinition {
        service: "unknown",
        number: 65000,
    },
    PortDefinition {
        service: "unknown",
        number: 64680,
    },
    PortDefinition {
        service: "unknown",
        number: 64623,
    },
    PortDefinition {
        service: "unknown",
        number: 55600,
    },
    PortDefinition {
        service: "unknown",
        number: 55555,
    },
    PortDefinition {
        service: "unknown",
        number: 52869,
    },
    PortDefinition {
        service: "unknown",
        number: 35500,
    },
    PortDefinition {
        service: "unknown",
        number: 33354,
    },
    PortDefinition {
        service: "unknown",
        number: 23502,
    },
    PortDefinition {
        service: "unknown",
        number: 20828,
    },
    PortDefinition {
        service: "rxmon",
        number: 1311,
    },
    PortDefinition {
        service: "polestar",
        number: 1060,
    },
    PortDefinition {
        service: "pharos",
        number: 4443,
    },
    PortDefinition {
        service: "instl_boots",
        number: 1067,
    },
    PortDefinition {
        service: "netbackup",
        number: 13782,
    },
    PortDefinition {
        service: "vnc-2",
        number: 5902,
    },
    PortDefinition {
        service: "odmr",
        number: 366,
    },
    PortDefinition {
        service: "tor-socks",
        number: 9050,
    },
    PortDefinition {
        service: "windows-icfw",
        number: 1002,
    },
    PortDefinition {
        service: "mit-ml-dev",
        number: 85,
    },
    PortDefinition {
        service: "hotline",
        number: 5500,
    },
    PortDefinition {
        service: "park-agent",
        number: 5431,
    },
    PortDefinition {
        service: "paradym-31",
        number: 1864,
    },
    PortDefinition {
        service: "msnp",
        number: 1863,
    },
    PortDefinition {
        service: "unknown",
        number: 8085,
    },
    PortDefinition {
        service: "unknown",
        number: 51103,
    },
    PortDefinition {
        service: "unknown",
        number: 49999,
    },
    PortDefinition {
        service: "unknown",
        number: 45100,
    },
    PortDefinition {
        service: "unknown",
        number: 10243,
    },
    PortDefinition {
        service: "tacacs",
        number: 49,
    },
    PortDefinition {
        service: "irc",
        number: 6667,
    },
    PortDefinition {
        service: "dnsix",
        number: 90,
    },
    PortDefinition {
        service: "flexlm0",
        number: 27000,
    },
    PortDefinition {
        service: "imtc-mcs",
        number: 1503,
    },
    PortDefinition {
        service: "bittorrent-tracker",
        number: 6881,
    },
    PortDefinition {
        service: "vlsi-lm",
        number: 1500,
    },
    PortDefinition {
        service: "ftp-proxy",
        number: 8021,
    },
    PortDefinition {
        service: "unknown",
        number: 340,
    },
    PortDefinition {
        service: "westec-connect",
        number: 5566,
    },
    PortDefinition {
        service: "radan-http",
        number: 8088,
    },
    PortDefinition {
        service: "EtherNetIP-1",
        number: 2222,
    },
    PortDefinition {
        service: "unknown",
        number: 9071,
    },
    PortDefinition {
        service: "ospf-lite",
        number: 8899,
    },
    PortDefinition {
        service: "X11:5",
        number: 6005,
    },
    PortDefinition {
        service: "sd",
        number: 9876,
    },
    PortDefinition {
        service: "sas-3",
        number: 1501,
    },
    PortDefinition {
        service: "admeng",
        number: 5102,
    },
    PortDefinition {
        service: "sometimes-rpc11",
        number: 32774,
    },
    PortDefinition {
        service: "sometimes-rpc9",
        number: 32773,
    },
    PortDefinition {
        service: "jetdirect",
        number: 9101,
    },
    PortDefinition {
        service: "activesync",
        number: 5679,
    },
    PortDefinition {
        service: "cmip-man",
        number: 163,
    },
    PortDefinition {
        service: "rrp",
        number: 648,
    },
    PortDefinition {
        service: "iso-tp0",
        number: 146,
    },
    PortDefinition {
        service: "netview-aix-6",
        number: 1666,
    },
    PortDefinition {
        service: "samba-swat",
        number: 901,
    },
    PortDefinition {
        service: "mit-ml-dev",
        number: 83,
    },
    PortDefinition {
        service: "wap-vcal-s",
        number: 9207,
    },
    PortDefinition {
        service: "vcom-tunnel",
        number: 8001,
    },
    PortDefinition {
        service: "us-srv",
        number: 8083,
    },
    PortDefinition {
        service: "websnp",
        number: 8084,
    },
    PortDefinition {
        service: "avt-profile-1",
        number: 5004,
    },
    PortDefinition {
        service: "nppmp",
        number: 3476,
    },
    PortDefinition {
        service: "unknown",
        number: 5214,
    },
    PortDefinition {
        service: "unknown",
        number: 14238,
    },
    PortDefinition {
        service: "netbus",
        number: 12345,
    },
    PortDefinition {
        service: "apex-mesh",
        number: 912,
    },
    PortDefinition {
        service: "unknown",
        number: 30,
    },
    PortDefinition {
        service: "bgpd",
        number: 2605,
    },
    PortDefinition {
        service: "device2",
        number: 2030,
    },
    PortDefinition {
        service: "unknown",
        number: 6,
    },
    PortDefinition {
        service: "uucp-rlogin",
        number: 541,
    },
    PortDefinition {
        service: "ajp12",
        number: 8007,
    },
    PortDefinition {
        service: "deslogin",
        number: 3005,
    },
    PortDefinition {
        service: "unknown",
        number: 4,
    },
    PortDefinition {
        service: "hermes",
        number: 1248,
    },
    PortDefinition {
        service: "rtsserv",
        number: 2500,
    },
    PortDefinition {
        service: "unknown",
        number: 880,
    },
    PortDefinition {
        service: "unknown",
        number: 306,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4242,
    },
    PortDefinition {
        service: "sunclustermgr",
        number: 1097,
    },
    PortDefinition {
        service: "pichat",
        number: 9009,
    },
    PortDefinition {
        service: "ms-v-worlds",
        number: 2525,
    },
    PortDefinition {
        service: "cplscrambler-lg",
        number: 1086,
    },
    PortDefinition {
        service: "cplscrambler-al",
        number: 1088,
    },
    PortDefinition {
        service: "unknown",
        number: 8291,
    },
    PortDefinition {
        service: "unknown",
        number: 52822,
    },
    PortDefinition {
        service: "backupexec",
        number: 6101,
    },
    PortDefinition {
        service: "omginitialrefs",
        number: 900,
    },
    PortDefinition {
        service: "fodms",
        number: 7200,
    },
    PortDefinition {
        service: "corbaloc",
        number: 2809,
    },
    PortDefinition {
        service: "mdbs_daemon",
        number: 800,
    },
    PortDefinition {
        service: "sometimes-rpc13",
        number: 32775,
    },
    PortDefinition {
        service: "cce4x",
        number: 12000,
    },
    PortDefinition {
        service: "ansoft-lm-1",
        number: 1083,
    },
    PortDefinition {
        service: "914c-g",
        number: 211,
    },
    PortDefinition {
        service: "unknown",
        number: 987,
    },
    PortDefinition {
        service: "agentx",
        number: 705,
    },
    PortDefinition {
        service: "btx",
        number: 20005,
    },
    PortDefinition {
        service: "cisco-tdp",
        number: 711,
    },
    PortDefinition {
        service: "netbackup",
        number: 13783,
    },
    PortDefinition {
        service: "acmsoda",
        number: 6969,
    },
    PortDefinition {
        service: "csd-mgmt-port",
        number: 3071,
    },
    PortDefinition {
        service: "xmpp-server",
        number: 5269,
    },
    PortDefinition {
        service: "xmpp-client",
        number: 5222,
    },
    PortDefinition {
        service: "wfremotertm",
        number: 1046,
    },
    PortDefinition {
        service: "webobjects",
        number: 1085,
    },
    PortDefinition {
        service: "wbem-rmi",
        number: 5987,
    },
    PortDefinition {
        service: "wbem-https",
        number: 5989,
    },
    PortDefinition {
        service: "wbem-http",
        number: 5988,
    },
    PortDefinition {
        service: "tivoconnect",
        number: 2190,
    },
    PortDefinition {
        service: "sysinfo-sp",
        number: 11967,
    },
    PortDefinition {
        service: "asterix",
        number: 8600,
    },
    PortDefinition {
        service: "sitewatch-s",
        number: 3766,
    },
    PortDefinition {
        service: "soap-http",
        number: 7627,
    },
    PortDefinition {
        service: "simplifymedia",
        number: 8087,
    },
    PortDefinition {
        service: "ndmps",
        number: 30000,
    },
    PortDefinition {
        service: "sdr",
        number: 9010,
    },
    PortDefinition {
        service: "scriptview",
        number: 7741,
    },
    PortDefinition {
        service: "scotty-ft",
        number: 14000,
    },
    PortDefinition {
        service: "satvid-datalnk",
        number: 3367,
    },
    PortDefinition {
        service: "rmiregistry",
        number: 1099,
    },
    PortDefinition {
        service: "rmiactivation",
        number: 1098,
    },
    PortDefinition {
        service: "eppc",
        number: 3031,
    },
    PortDefinition {
        service: "pn-requester2",
        number: 2718,
    },
    PortDefinition {
        service: "parsec-master",
        number: 6580,
    },
    PortDefinition {
        service: "onep-tls",
        number: 15002,
    },
    PortDefinition {
        service: "nuauth",
        number: 4129,
    },
    PortDefinition {
        service: "jetstream",
        number: 6901,
    },
    PortDefinition {
        service: "netmpi",
        number: 3827,
    },
    PortDefinition {
        service: "nati-svrloc",
        number: 3580,
    },
    PortDefinition {
        service: "lv-ffx",
        number: 2144,
    },
    PortDefinition {
        service: "iua",
        number: 9900,
    },
    PortDefinition {
        service: "intermapper",
        number: 8181,
    },
    PortDefinition {
        service: "ibm-mgr",
        number: 3801,
    },
    PortDefinition {
        service: "h323gatedisc",
        number: 1718,
    },
    PortDefinition {
        service: "gsiftp",
        number: 2811,
    },
    PortDefinition {
        service: "glrpc",
        number: 9080,
    },
    PortDefinition {
        service: "gris",
        number: 2135,
    },
    PortDefinition {
        service: "fpitp",
        number: 1045,
    },
    PortDefinition {
        service: "fmpro-fdal",
        number: 2399,
    },
    PortDefinition {
        service: "event_listener",
        number: 3017,
    },
    PortDefinition {
        service: "documentum",
        number: 10002,
    },
    PortDefinition {
        service: "elfiq-repl",
        number: 1148,
    },
    PortDefinition {
        service: "dynamid",
        number: 9002,
    },
    PortDefinition {
        service: "dxspider",
        number: 8873,
    },
    PortDefinition {
        service: "dxmessagebase2",
        number: 2875,
    },
    PortDefinition {
        service: "d-star",
        number: 9011,
    },
    PortDefinition {
        service: "dpm",
        number: 5718,
    },
    PortDefinition {
        service: "d-s-n",
        number: 8086,
    },
    PortDefinition {
        service: "dnx",
        number: 3998,
    },
    PortDefinition {
        service: "connection",
        number: 2607,
    },
    PortDefinition {
        service: "sgi-soap",
        number: 11110,
    },
    PortDefinition {
        service: "ddrepl",
        number: 4126,
    },
    PortDefinition {
        service: "cpdlc",
        number: 5911,
    },
    PortDefinition {
        service: "cm",
        number: 5910,
    },
    PortDefinition {
        service: "condor",
        number: 9618,
    },
    PortDefinition {
        service: "compaq-https",
        number: 2381,
    },
    PortDefinition {
        service: "cnrprotocol",
        number: 1096,
    },
    PortDefinition {
        service: "ceph",
        number: 3300,
    },
    PortDefinition {
        service: "btrieve",
        number: 3351,
    },
    PortDefinition {
        service: "bridgecontrol",
        number: 1073,
    },
    PortDefinition {
        service: "bitcoin",
        number: 8333,
    },
    PortDefinition {
        service: "bfd-control",
        number: 3784,
    },
    PortDefinition {
        service: "beorl",
        number: 5633,
    },
    PortDefinition {
        service: "bex-xr",
        number: 15660,
    },
    PortDefinition {
        service: "backup-express",
        number: 6123,
    },
    PortDefinition {
        service: "avsecuremgmt",
        number: 3211,
    },
    PortDefinition {
        service: "avocent-proxy",
        number: 1078,
    },
    PortDefinition {
        service: "apple-sasl",
        number: 3659,
    },
    PortDefinition {
        service: "apcupsd",
        number: 3551,
    },
    PortDefinition {
        service: "apc-2260",
        number: 2260,
    },
    PortDefinition {
        service: "apc-2160",
        number: 2160,
    },
    PortDefinition {
        service: "amiganetfs",
        number: 2100,
    },
    PortDefinition {
        service: "fmsascon",
        number: 16001,
    },
    PortDefinition {
        service: "active-net",
        number: 3325,
    },
    PortDefinition {
        service: "active-net",
        number: 3323,
    },
    PortDefinition {
        service: "xrl",
        number: 1104,
    },
    PortDefinition {
        service: "unknown",
        number: 9968,
    },
    PortDefinition {
        service: "unknown",
        number: 9503,
    },
    PortDefinition {
        service: "unknown",
        number: 9502,
    },
    PortDefinition {
        service: "unknown",
        number: 9485,
    },
    PortDefinition {
        service: "unknown",
        number: 9290,
    },
    PortDefinition {
        service: "unknown",
        number: 9220,
    },
    PortDefinition {
        service: "unknown",
        number: 8994,
    },
    PortDefinition {
        service: "unknown",
        number: 8649,
    },
    PortDefinition {
        service: "unknown",
        number: 8222,
    },
    PortDefinition {
        service: "unknown",
        number: 7911,
    },
    PortDefinition {
        service: "unknown",
        number: 7625,
    },
    PortDefinition {
        service: "unknown",
        number: 7106,
    },
    PortDefinition {
        service: "unknown",
        number: 65129,
    },
    PortDefinition {
        service: "unknown",
        number: 63331,
    },
    PortDefinition {
        service: "unknown",
        number: 6156,
    },
    PortDefinition {
        service: "unknown",
        number: 6129,
    },
    PortDefinition {
        service: "unknown",
        number: 60020,
    },
    PortDefinition {
        service: "unknown",
        number: 5962,
    },
    PortDefinition {
        service: "unknown",
        number: 5961,
    },
    PortDefinition {
        service: "unknown",
        number: 5960,
    },
    PortDefinition {
        service: "unknown",
        number: 5959,
    },
    PortDefinition {
        service: "unknown",
        number: 5925,
    },
    PortDefinition {
        service: "unknown",
        number: 5877,
    },
    PortDefinition {
        service: "unknown",
        number: 5825,
    },
    PortDefinition {
        service: "unknown",
        number: 5810,
    },
    PortDefinition {
        service: "unknown",
        number: 58080,
    },
    PortDefinition {
        service: "unknown",
        number: 57294,
    },
    PortDefinition {
        service: "unknown",
        number: 50800,
    },
    PortDefinition {
        service: "unknown",
        number: 50006,
    },
    PortDefinition {
        service: "unknown",
        number: 50003,
    },
    PortDefinition {
        service: "unknown",
        number: 49160,
    },
    PortDefinition {
        service: "unknown",
        number: 49159,
    },
    PortDefinition {
        service: "unknown",
        number: 49158,
    },
    PortDefinition {
        service: "unknown",
        number: 48080,
    },
    PortDefinition {
        service: "unknown",
        number: 40193,
    },
    PortDefinition {
        service: "unknown",
        number: 34573,
    },
    PortDefinition {
        service: "unknown",
        number: 34572,
    },
    PortDefinition {
        service: "unknown",
        number: 34571,
    },
    PortDefinition {
        service: "unknown",
        number: 3404,
    },
    PortDefinition {
        service: "unknown",
        number: 33899,
    },
    PortDefinition {
        service: "unknown",
        number: 3301,
    },
    PortDefinition {
        service: "unknown",
        number: 32782,
    },
    PortDefinition {
        service: "unknown",
        number: 32781,
    },
    PortDefinition {
        service: "unknown",
        number: 31038,
    },
    PortDefinition {
        service: "unknown",
        number: 30718,
    },
    PortDefinition {
        service: "unknown",
        number: 28201,
    },
    PortDefinition {
        service: "unknown",
        number: 27715,
    },
    PortDefinition {
        service: "unknown",
        number: 25734,
    },
    PortDefinition {
        service: "unknown",
        number: 24800,
    },
    PortDefinition {
        service: "unknown",
        number: 22939,
    },
    PortDefinition {
        service: "unknown",
        number: 21571,
    },
    PortDefinition {
        service: "unknown",
        number: 20221,
    },
    PortDefinition {
        service: "unknown",
        number: 20031,
    },
    PortDefinition {
        service: "unknown",
        number: 19842,
    },
    PortDefinition {
        service: "unknown",
        number: 19801,
    },
    PortDefinition {
        service: "unknown",
        number: 19101,
    },
    PortDefinition {
        service: "unknown",
        number: 17988,
    },
    PortDefinition {
        service: "unknown",
        number: 1783,
    },
    PortDefinition {
        service: "unknown",
        number: 16018,
    },
    PortDefinition {
        service: "unknown",
        number: 16016,
    },
    PortDefinition {
        service: "unknown",
        number: 15003,
    },
    PortDefinition {
        service: "unknown",
        number: 14442,
    },
    PortDefinition {
        service: "unknown",
        number: 13456,
    },
    PortDefinition {
        service: "unknown",
        number: 10629,
    },
    PortDefinition {
        service: "unknown",
        number: 10628,
    },
    PortDefinition {
        service: "unknown",
        number: 10626,
    },
    PortDefinition {
        service: "unknown",
        number: 10621,
    },
    PortDefinition {
        service: "unknown",
        number: 10617,
    },
    PortDefinition {
        service: "unknown",
        number: 10616,
    },
    PortDefinition {
        service: "unknown",
        number: 10566,
    },
    PortDefinition {
        service: "unknown",
        number: 10025,
    },
    PortDefinition {
        service: "unknown",
        number: 10024,
    },
    PortDefinition {
        service: "unknown",
        number: 10012,
    },
    PortDefinition {
        service: "tripwire",
        number: 1169,
    },
    PortDefinition {
        service: "surfpass",
        number: 5030,
    },
    PortDefinition {
        service: "statusd",
        number: 5414,
    },
    PortDefinition {
        service: "startron",
        number: 1057,
    },
    PortDefinition {
        service: "smc-http",
        number: 6788,
    },
    PortDefinition {
        service: "sentinelsrm",
        number: 1947,
    },
    PortDefinition {
        service: "rootd",
        number: 1094,
    },
    PortDefinition {
        service: "rdrmshc",
        number: 1075,
    },
    PortDefinition {
        service: "ratio-adp",
        number: 1108,
    },
    PortDefinition {
        service: "pxc-splr-ft",
        number: 4003,
    },
    PortDefinition {
        service: "pvuniwien",
        number: 1081,
    },
    PortDefinition {
        service: "proofd",
        number: 1093,
    },
    PortDefinition {
        service: "privatewire",
        number: 4449,
    },
    PortDefinition {
        service: "nsjtp-ctrl",
        number: 1687,
    },
    PortDefinition {
        service: "netopia-vo2",
        number: 1840,
    },
    PortDefinition {
        service: "mctp",
        number: 1100,
    },
    PortDefinition {
        service: "kyoceranetdev",
        number: 1063,
    },
    PortDefinition {
        service: "kiosk",
        number: 1061,
    },
    PortDefinition {
        service: "isoipsigport-2",
        number: 1107,
    },
    PortDefinition {
        service: "isoipsigport-1",
        number: 1106,
    },
    PortDefinition {
        service: "ismserver",
        number: 9500,
    },
    PortDefinition {
        service: "ipulse-ics",
        number: 20222,
    },
    PortDefinition {
        service: "interwise",
        number: 7778,
    },
    PortDefinition {
        service: "imgames",
        number: 1077,
    },
    PortDefinition {
        service: "husky",
        number: 1310,
    },
    PortDefinition {
        service: "gsigatekeeper",
        number: 2119,
    },
    PortDefinition {
        service: "groove",
        number: 2492,
    },
    PortDefinition {
        service: "gmrupdateserv",
        number: 1070,
    },
    PortDefinition {
        service: "dnp",
        number: 20000,
    },
    PortDefinition {
        service: "cvd",
        number: 8400,
    },
    PortDefinition {
        service: "cspmlockmgr",
        number: 1272,
    },
    PortDefinition {
        service: "clariion-evr01",
        number: 6389,
    },
    PortDefinition {
        service: "cbt",
        number: 7777,
    },
    PortDefinition {
        service: "cardax",
        number: 1072,
    },
    PortDefinition {
        service: "asprovatalk",
        number: 1079,
    },
    PortDefinition {
        service: "amt-esd-prot",
        number: 1082,
    },
    PortDefinition {
        service: "abarsd",
        number: 8402,
    },
    PortDefinition {
        service: "su-mit-tg",
        number: 89,
    },
    PortDefinition {
        service: "resvc",
        number: 691,
    },
    PortDefinition {
        service: "webpush",
        number: 1001,
    },
    PortDefinition {
        service: "sometimes-rpc15",
        number: 32776,
    },
    PortDefinition {
        service: "tcp-id-port",
        number: 1999,
    },
    PortDefinition {
        service: "anet",
        number: 212,
    },
    PortDefinition {
        service: "xinupageserver",
        number: 2020,
    },
    PortDefinition {
        service: "X11:3",
        number: 6003,
    },
    PortDefinition {
        service: "afs3-prserver",
        number: 7002,
    },
    PortDefinition {
        service: "iss-realsec",
        number: 2998,
    },
    PortDefinition {
        service: "iiimsf",
        number: 50002,
    },
    PortDefinition {
        service: "msdtc",
        number: 3372,
    },
    PortDefinition {
        service: "sun-manageconsole",
        number: 898,
    },
    PortDefinition {
        service: "secureidprop",
        number: 5510,
    },
    PortDefinition {
        service: "unknown",
        number: 32,
    },
    PortDefinition {
        service: "glogger",
        number: 2033,
    },
    PortDefinition {
        service: "vnc-3",
        number: 5903,
    },
    PortDefinition {
        service: "metagram",
        number: 99,
    },
    PortDefinition {
        service: "kerberos-adm",
        number: 749,
    },
    PortDefinition {
        service: "icad-el",
        number: 425,
    },
    PortDefinition {
        service: "whois",
        number: 43,
    },
    PortDefinition {
        service: "pcduo",
        number: 5405,
    },
    PortDefinition {
        service: "isdninfo",
        number: 6106,
    },
    PortDefinition {
        service: "netbackup",
        number: 13722,
    },
    PortDefinition {
        service: "netop-rc",
        number: 6502,
    },
    PortDefinition {
        service: "afs3-bos",
        number: 7007,
    },
    PortDefinition {
        service: "appleqtc",
        number: 458,
    },
    PortDefinition {
        service: "zoomcp",
        number: 9666,
    },
    PortDefinition {
        service: "xprint-server",
        number: 8100,
    },
    PortDefinition {
        service: "xpanel",
        number: 3737,
    },
    PortDefinition {
        service: "presence",
        number: 5298,
    },
    PortDefinition {
        service: "winpoplanmess",
        number: 1152,
    },
    PortDefinition {
        service: "opsmessaging",
        number: 8090,
    },
    PortDefinition {
        service: "tvbus",
        number: 2191,
    },
    PortDefinition {
        service: "trusted-web",
        number: 3011,
    },
    PortDefinition {
        service: "tn-tl-r1",
        number: 1580,
    },
    PortDefinition {
        service: "x510",
        number: 9877,
    },
    PortDefinition {
        service: "targus-getdata",
        number: 5200,
    },
    PortDefinition {
        service: "spectraport",
        number: 3851,
    },
    PortDefinition {
        service: "satvid-datalnk",
        number: 3371,
    },
    PortDefinition {
        service: "satvid-datalnk",
        number: 3370,
    },
    PortDefinition {
        service: "satvid-datalnk",
        number: 3369,
    },
    PortDefinition {
        service: "rtps-dd-mt",
        number: 7402,
    },
    PortDefinition {
        service: "rlm-admin",
        number: 5054,
    },
    PortDefinition {
        service: "pktcablemmcops",
        number: 3918,
    },
    PortDefinition {
        service: "orbix-loc-ssl",
        number: 3077,
    },
    PortDefinition {
        service: "oracleas-https",
        number: 7443,
    },
    PortDefinition {
        service: "nut",
        number: 3493,
    },
    PortDefinition {
        service: "neteh",
        number: 3828,
    },
    PortDefinition {
        service: "mysql-cluster",
        number: 1186,
    },
    PortDefinition {
        service: "vmrdp",
        number: 2179,
    },
    PortDefinition {
        service: "llsurfup-http",
        number: 1183,
    },
    PortDefinition {
        service: "keyshadow",
        number: 19315,
    },
    PortDefinition {
        service: "keysrvr",
        number: 19283,
    },
    PortDefinition {
        service: "iss-mgmt-ssl",
        number: 3995,
    },
    PortDefinition {
        service: "indy",
        number: 5963,
    },
    PortDefinition {
        service: "hpvmmcontrol",
        number: 1124,
    },
    PortDefinition {
        service: "fmtp",
        number: 8500,
    },
    PortDefinition {
        service: "ff-annunc",
        number: 1089,
    },
    PortDefinition {
        service: "emcrmirccd",
        number: 10004,
    },
    PortDefinition {
        service: "dif-port",
        number: 2251,
    },
    PortDefinition {
        service: "cplscrambler-in",
        number: 1087,
    },
    PortDefinition {
        service: "xmpp-bosh",
        number: 5280,
    },
    PortDefinition {
        service: "avocent-adsap",
        number: 3871,
    },
    PortDefinition {
        service: "arepa-cas",
        number: 3030,
    },
    PortDefinition {
        service: "iphone-sync",
        number: 62078,
    },
    PortDefinition {
        service: "xmltec-xmlmail",
        number: 9091,
    },
    PortDefinition {
        service: "xgrid",
        number: 4111,
    },
    PortDefinition {
        service: "writesrv",
        number: 1334,
    },
    PortDefinition {
        service: "winshadow",
        number: 3261,
    },
    PortDefinition {
        service: "windb",
        number: 2522,
    },
    PortDefinition {
        service: "wherehoo",
        number: 5859,
    },
    PortDefinition {
        service: "visionpyramid",
        number: 1247,
    },
    PortDefinition {
        service: "unknown",
        number: 9944,
    },
    PortDefinition {
        service: "unknown",
        number: 9943,
    },
    PortDefinition {
        service: "unknown",
        number: 9110,
    },
    PortDefinition {
        service: "unknown",
        number: 8654,
    },
    PortDefinition {
        service: "unknown",
        number: 8254,
    },
    PortDefinition {
        service: "unknown",
        number: 8180,
    },
    PortDefinition {
        service: "unknown",
        number: 8011,
    },
    PortDefinition {
        service: "unknown",
        number: 7512,
    },
    PortDefinition {
        service: "unknown",
        number: 7435,
    },
    PortDefinition {
        service: "unknown",
        number: 7103,
    },
    PortDefinition {
        service: "unknown",
        number: 61900,
    },
    PortDefinition {
        service: "unknown",
        number: 61532,
    },
    PortDefinition {
        service: "unknown",
        number: 5922,
    },
    PortDefinition {
        service: "unknown",
        number: 5915,
    },
    PortDefinition {
        service: "unknown",
        number: 5904,
    },
    PortDefinition {
        service: "unknown",
        number: 5822,
    },
    PortDefinition {
        service: "unknown",
        number: 56738,
    },
    PortDefinition {
        service: "unknown",
        number: 55055,
    },
    PortDefinition {
        service: "unknown",
        number: 51493,
    },
    PortDefinition {
        service: "unknown",
        number: 50636,
    },
    PortDefinition {
        service: "unknown",
        number: 50389,
    },
    PortDefinition {
        service: "unknown",
        number: 49175,
    },
    PortDefinition {
        service: "unknown",
        number: 49165,
    },
    PortDefinition {
        service: "unknown",
        number: 49163,
    },
    PortDefinition {
        service: "unknown",
        number: 3546,
    },
    PortDefinition {
        service: "unknown",
        number: 32784,
    },
    PortDefinition {
        service: "unknown",
        number: 27355,
    },
    PortDefinition {
        service: "unknown",
        number: 27353,
    },
    PortDefinition {
        service: "unknown",
        number: 27352,
    },
    PortDefinition {
        service: "unknown",
        number: 24444,
    },
    PortDefinition {
        service: "unknown",
        number: 19780,
    },
    PortDefinition {
        service: "unknown",
        number: 18988,
    },
    PortDefinition {
        service: "unknown",
        number: 16012,
    },
    PortDefinition {
        service: "unknown",
        number: 15742,
    },
    PortDefinition {
        service: "unknown",
        number: 10778,
    },
    PortDefinition {
        service: "pxc-spvr",
        number: 4006,
    },
    PortDefinition {
        service: "pktcable-cops",
        number: 2126,
    },
    PortDefinition {
        service: "n1-fwp",
        number: 4446,
    },
    PortDefinition {
        service: "igrs",
        number: 3880,
    },
    PortDefinition {
        service: "hp-hcip",
        number: 1782,
    },
    PortDefinition {
        service: "dproxy",
        number: 1296,
    },
    PortDefinition {
        service: "distinct32",
        number: 9998,
    },
    PortDefinition {
        service: "tor-trans",
        number: 9040,
    },
    PortDefinition {
        service: "sometimes-rpc21",
        number: 32779,
    },
    PortDefinition {
        service: "exp1",
        number: 1021,
    },
    PortDefinition {
        service: "sometimes-rpc17",
        number: 32777,
    },
    PortDefinition {
        service: "servexec",
        number: 2021,
    },
    PortDefinition {
        service: "sometimes-rpc19",
        number: 32778,
    },
    PortDefinition {
        service: "sco-sysmgr",
        number: 616,
    },
    PortDefinition {
        service: "doom",
        number: 666,
    },
    PortDefinition {
        service: "epp",
        number: 700,
    },
    PortDefinition {
        service: "vnc-http-2",
        number: 5802,
    },
    PortDefinition {
        service: "rwhois",
        number: 4321,
    },
    PortDefinition {
        service: "ekshell",
        number: 545,
    },
    PortDefinition {
        service: "ingreslock",
        number: 1524,
    },
    PortDefinition {
        service: "msql",
        number: 1112,
    },
    PortDefinition {
        service: "compaqdiag",
        number: 49400,
    },
    PortDefinition {
        service: "ctf",
        number: 84,
    },
    PortDefinition {
        service: "landesk-cba",
        number: 38292,
    },
    PortDefinition {
        service: "lam",
        number: 2040,
    },
    PortDefinition {
        service: "sometimes-rpc23",
        number: 32780,
    },
    PortDefinition {
        service: "deslogind",
        number: 3006,
    },
    PortDefinition {
        service: "kx",
        number: 2111,
    },
    PortDefinition {
        service: "ansoft-lm-2",
        number: 1084,
    },
    PortDefinition {
        service: "issd",
        number: 1600,
    },
    PortDefinition {
        service: "dls-monitor",
        number: 2048,
    },
    PortDefinition {
        service: "sybase",
        number: 2638,
    },
    PortDefinition {
        service: "DragonIDSConsole",
        number: 9111,
    },
    PortDefinition {
        service: "napster",
        number: 6699,
    },
    PortDefinition {
        service: "osxwebadmin",
        number: 16080,
    },
    PortDefinition {
        service: "powerchuteplus",
        number: 6547,
    },
    PortDefinition {
        service: "X11:7",
        number: 6007,
    },
    PortDefinition {
        service: "virtual-places",
        number: 1533,
    },
    PortDefinition {
        service: "isqlplus",
        number: 5560,
    },
    PortDefinition {
        service: "ekshell",
        number: 2106,
    },
    PortDefinition {
        service: "ies-lm",
        number: 1443,
    },
    PortDefinition {
        service: "disclose",
        number: 667,
    },
    PortDefinition {
        service: "unknown",
        number: 720,
    },
    PortDefinition {
        service: "scoremgr",
        number: 2034,
    },
    PortDefinition {
        service: "dsf",
        number: 555,
    },
    PortDefinition {
        service: "device",
        number: 801,
    },
    PortDefinition {
        service: "xnm-clear-text",
        number: 3221,
    },
    PortDefinition {
        service: "x11",
        number: 6025,
    },
    PortDefinition {
        service: "wormux",
        number: 3826,
    },
    PortDefinition {
        service: "wap-wsp",
        number: 9200,
    },
    PortDefinition {
        service: "wag-service",
        number: 2608,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4279,
    },
    PortDefinition {
        service: "vmsvc-2",
        number: 7025,
    },
    PortDefinition {
        service: "vce",
        number: 11111,
    },
    PortDefinition {
        service: "beserver-msg-q",
        number: 3527,
    },
    PortDefinition {
        service: "unizensus",
        number: 1151,
    },
    PortDefinition {
        service: "trivnet1",
        number: 8200,
    },
    PortDefinition {
        service: "tmi",
        number: 8300,
    },
    PortDefinition {
        service: "tsa",
        number: 6689,
    },
    PortDefinition {
        service: "kca-service",
        number: 9878,
    },
    PortDefinition {
        service: "swdtp-sv",
        number: 10009,
    },
    PortDefinition {
        service: "sunwebadmin",
        number: 8800,
    },
    PortDefinition {
        service: "unieng",
        number: 5730,
    },
    PortDefinition {
        service: "ms-olap2",
        number: 2394,
    },
    PortDefinition {
        service: "ms-olap1",
        number: 2393,
    },
    PortDefinition {
        service: "msolap-ptp2",
        number: 2725,
    },
    PortDefinition {
        service: "sip-tls",
        number: 5061,
    },
    PortDefinition {
        service: "sane-port",
        number: 6566,
    },
    PortDefinition {
        service: "cisco-aqos",
        number: 9081,
    },
    PortDefinition {
        service: "rrac",
        number: 5678,
    },
    PortDefinition {
        service: "pwgpsi",
        number: 3800,
    },
    PortDefinition {
        service: "gds-adppiw-db",
        number: 4550,
    },
    PortDefinition {
        service: "onscreen",
        number: 5080,
    },
    PortDefinition {
        service: "nucleus-sand",
        number: 1201,
    },
    PortDefinition {
        service: "poweronnud",
        number: 3168,
    },
    PortDefinition {
        service: "neto-dcs",
        number: 3814,
    },
    PortDefinition {
        service: "mysql-cm-agent",
        number: 1862,
    },
    PortDefinition {
        service: "mini-sql",
        number: 1114,
    },
    PortDefinition {
        service: "mcer-port",
        number: 6510,
    },
    PortDefinition {
        service: "mupdate",
        number: 3905,
    },
    PortDefinition {
        service: "m2mservices",
        number: 8383,
    },
    PortDefinition {
        service: "listcrt-port-2",
        number: 3914,
    },
    PortDefinition {
        service: "lanrevserver",
        number: 3971,
    },
    PortDefinition {
        service: "apocd",
        number: 3809,
    },
    PortDefinition {
        service: "jtnetd-server",
        number: 5033,
    },
    PortDefinition {
        service: "imqbrokerd",
        number: 7676,
    },
    PortDefinition {
        service: "802-11-iapp",
        number: 3517,
    },
    PortDefinition {
        service: "hfcs",
        number: 4900,
    },
    PortDefinition {
        service: "ovsam-mgmt",
        number: 3869,
    },
    PortDefinition {
        service: "git",
        number: 9418,
    },
    PortDefinition {
        service: "funk-dialout",
        number: 2909,
    },
    PortDefinition {
        service: "fotogcad",
        number: 3878,
    },
    PortDefinition {
        service: "fs-agent",
        number: 8042,
    },
    PortDefinition {
        service: "ff-sm",
        number: 1091,
    },
    PortDefinition {
        service: "ff-fms",
        number: 1090,
    },
    PortDefinition {
        service: "exasoftport1",
        number: 3920,
    },
    PortDefinition {
        service: "esp",
        number: 6567,
    },
    PortDefinition {
        service: "encrypted_admin",
        number: 1138,
    },
    PortDefinition {
        service: "emcads",
        number: 3945,
    },
    PortDefinition {
        service: "dossier",
        number: 1175,
    },
    PortDefinition {
        service: "documentum_s",
        number: 10003,
    },
    PortDefinition {
        service: "dsc",
        number: 3390,
    },
    PortDefinition {
        service: "dandv-tester",
        number: 3889,
    },
    PortDefinition {
        service: "caspssl",
        number: 1131,
    },
    PortDefinition {
        service: "blp3",
        number: 8292,
    },
    PortDefinition {
        service: "biotic",
        number: 5087,
    },
    PortDefinition {
        service: "bnetgame",
        number: 1119,
    },
    PortDefinition {
        service: "ardus-mtrns",
        number: 1117,
    },
    PortDefinition {
        service: "asr",
        number: 7800,
    },
    PortDefinition {
        service: "appserv-http",
        number: 4848,
    },
    PortDefinition {
        service: "fmsas",
        number: 16000,
    },
    PortDefinition {
        service: "active-net",
        number: 3324,
    },
    PortDefinition {
        service: "active-net",
        number: 3322,
    },
    PortDefinition {
        service: "3exmp",
        number: 5221,
    },
    PortDefinition {
        service: "upnotifyp",
        number: 4445,
    },
    PortDefinition {
        service: "unknown",
        number: 9917,
    },
    PortDefinition {
        service: "unknown",
        number: 9575,
    },
    PortDefinition {
        service: "unknown",
        number: 9099,
    },
    PortDefinition {
        service: "unknown",
        number: 9003,
    },
    PortDefinition {
        service: "unknown",
        number: 8290,
    },
    PortDefinition {
        service: "unknown",
        number: 8099,
    },
    PortDefinition {
        service: "unknown",
        number: 8093,
    },
    PortDefinition {
        service: "unknown",
        number: 8045,
    },
    PortDefinition {
        service: "unknown",
        number: 7921,
    },
    PortDefinition {
        service: "unknown",
        number: 7920,
    },
    PortDefinition {
        service: "unknown",
        number: 7496,
    },
    PortDefinition {
        service: "unknown",
        number: 6839,
    },
    PortDefinition {
        service: "unknown",
        number: 6792,
    },
    PortDefinition {
        service: "unknown",
        number: 6779,
    },
    PortDefinition {
        service: "unknown",
        number: 6692,
    },
    PortDefinition {
        service: "unknown",
        number: 6565,
    },
    PortDefinition {
        service: "unknown",
        number: 60443,
    },
    PortDefinition {
        service: "unknown",
        number: 5952,
    },
    PortDefinition {
        service: "unknown",
        number: 5950,
    },
    PortDefinition {
        service: "unknown",
        number: 5907,
    },
    PortDefinition {
        service: "unknown",
        number: 5906,
    },
    PortDefinition {
        service: "unknown",
        number: 5862,
    },
    PortDefinition {
        service: "unknown",
        number: 5850,
    },
    PortDefinition {
        service: "unknown",
        number: 5815,
    },
    PortDefinition {
        service: "unknown",
        number: 5811,
    },
    PortDefinition {
        service: "unknown",
        number: 57797,
    },
    PortDefinition {
        service: "unknown",
        number: 56737,
    },
    PortDefinition {
        service: "unknown",
        number: 5544,
    },
    PortDefinition {
        service: "unknown",
        number: 55056,
    },
    PortDefinition {
        service: "unknown",
        number: 5440,
    },
    PortDefinition {
        service: "unknown",
        number: 54328,
    },
    PortDefinition {
        service: "unknown",
        number: 54045,
    },
    PortDefinition {
        service: "unknown",
        number: 52848,
    },
    PortDefinition {
        service: "unknown",
        number: 52673,
    },
    PortDefinition {
        service: "unknown",
        number: 50500,
    },
    PortDefinition {
        service: "unknown",
        number: 50300,
    },
    PortDefinition {
        service: "unknown",
        number: 49176,
    },
    PortDefinition {
        service: "unknown",
        number: 49167,
    },
    PortDefinition {
        service: "unknown",
        number: 49161,
    },
    PortDefinition {
        service: "unknown",
        number: 44501,
    },
    PortDefinition {
        service: "unknown",
        number: 44176,
    },
    PortDefinition {
        service: "unknown",
        number: 41511,
    },
    PortDefinition {
        service: "unknown",
        number: 40911,
    },
    PortDefinition {
        service: "unknown",
        number: 32785,
    },
    PortDefinition {
        service: "unknown",
        number: 32783,
    },
    PortDefinition {
        service: "unknown",
        number: 30951,
    },
    PortDefinition {
        service: "unknown",
        number: 27356,
    },
    PortDefinition {
        service: "unknown",
        number: 26214,
    },
    PortDefinition {
        service: "unknown",
        number: 25735,
    },
    PortDefinition {
        service: "unknown",
        number: 19350,
    },
    PortDefinition {
        service: "unknown",
        number: 18101,
    },
    PortDefinition {
        service: "unknown",
        number: 18040,
    },
    PortDefinition {
        service: "unknown",
        number: 17877,
    },
    PortDefinition {
        service: "unknown",
        number: 16113,
    },
    PortDefinition {
        service: "unknown",
        number: 15004,
    },
    PortDefinition {
        service: "unknown",
        number: 14441,
    },
    PortDefinition {
        service: "unknown",
        number: 12265,
    },
    PortDefinition {
        service: "unknown",
        number: 12174,
    },
    PortDefinition {
        service: "unknown",
        number: 10215,
    },
    PortDefinition {
        service: "unknown",
        number: 10180,
    },
    PortDefinition {
        service: "tram",
        number: 4567,
    },
    PortDefinition {
        service: "synchronet-db",
        number: 6100,
    },
    PortDefinition {
        service: "pxc-roid",
        number: 4004,
    },
    PortDefinition {
        service: "pxc-pin",
        number: 4005,
    },
    PortDefinition {
        service: "oa-system",
        number: 8022,
    },
    PortDefinition {
        service: "monkeycom",
        number: 9898,
    },
    PortDefinition {
        service: "irdmi2",
        number: 7999,
    },
    PortDefinition {
        service: "excw",
        number: 1271,
    },
    PortDefinition {
        service: "dmidi",
        number: 1199,
    },
    PortDefinition {
        service: "cgms",
        number: 3003,
    },
    PortDefinition {
        service: "availant-mgr",
        number: 1122,
    },
    PortDefinition {
        service: "3d-nfsd",
        number: 2323,
    },
    PortDefinition {
        service: "xtell",
        number: 4224,
    },
    PortDefinition {
        service: "down",
        number: 2022,
    },
    PortDefinition {
        service: "sco-dtmgr",
        number: 617,
    },
    PortDefinition {
        service: "multiling-http",
        number: 777,
    },
    PortDefinition {
        service: "onmux",
        number: 417,
    },
    PortDefinition {
        service: "iris-xpcs",
        number: 714,
    },
    PortDefinition {
        service: "gnutella",
        number: 6346,
    },
    PortDefinition {
        service: "unknown",
        number: 981,
    },
    PortDefinition {
        service: "unknown",
        number: 722,
    },
    PortDefinition {
        service: "unknown",
        number: 1009,
    },
    PortDefinition {
        service: "maybe-veritas",
        number: 4998,
    },
    PortDefinition {
        service: "gopher",
        number: 70,
    },
    PortDefinition {
        service: "sns_credit",
        number: 1076,
    },
    PortDefinition {
        service: "ncd-conf",
        number: 5999,
    },
    PortDefinition {
        service: "amandaidx",
        number: 10082,
    },
    PortDefinition {
        service: "webster",
        number: 765,
    },
    PortDefinition {
        service: "unknown",
        number: 301,
    },
    PortDefinition {
        service: "ncp",
        number: 524,
    },
    PortDefinition {
        service: "mecomm",
        number: 668,
    },
    PortDefinition {
        service: "interbase",
        number: 2041,
    },
    PortDefinition {
        service: "X11:9",
        number: 6009,
    },
    PortDefinition {
        service: "timbuktu-srv1",
        number: 1417,
    },
    PortDefinition {
        service: "ms-sql-m",
        number: 1434,
    },
    PortDefinition {
        service: "esro-gen",
        number: 259,
    },
    PortDefinition {
        service: "coldfusion-auth",
        number: 44443,
    },
    PortDefinition {
        service: "bigbrother",
        number: 1984,
    },
    PortDefinition {
        service: "avocentkvm",
        number: 2068,
    },
    PortDefinition {
        service: "afs3-kaserver",
        number: 7004,
    },
    PortDefinition {
        service: "unknown",
        number: 1007,
    },
    PortDefinition {
        service: "unicall",
        number: 4343,
    },
    PortDefinition {
        service: "silverplatter",
        number: 416,
    },
    PortDefinition {
        service: "objectmanager",
        number: 2038,
    },
    PortDefinition {
        service: "X11:6",
        number: 6006,
    },
    PortDefinition {
        service: "pop2",
        number: 109,
    },
    PortDefinition {
        service: "rww",
        number: 4125,
    },
    PortDefinition {
        service: "ibm_wrless_lan",
        number: 1461,
    },
    PortDefinition {
        service: "jetdirect",
        number: 9103,
    },
    PortDefinition {
        service: "xact-backup",
        number: 911,
    },
    PortDefinition {
        service: "unknown",
        number: 726,
    },
    PortDefinition {
        service: "surf",
        number: 1010,
    },
    PortDefinition {
        service: "sdfunc",
        number: 2046,
    },
    PortDefinition {
        service: "imsldoc",
        number: 2035,
    },
    PortDefinition {
        service: "dlip",
        number: 7201,
    },
    PortDefinition {
        service: "asipregistry",
        number: 687,
    },
    PortDefinition {
        service: "raid-am",
        number: 2013,
    },
    PortDefinition {
        service: "dvs",
        number: 481,
    },
    PortDefinition {
        service: "locus-map",
        number: 125,
    },
    PortDefinition {
        service: "irc",
        number: 6669,
    },
    PortDefinition {
        service: "irc",
        number: 6668,
    },
    PortDefinition {
        service: "iss-console-mgr",
        number: 903,
    },
    PortDefinition {
        service: "esl-lm",
        number: 1455,
    },
    PortDefinition {
        service: "corba-iiop",
        number: 683,
    },
    PortDefinition {
        service: "unknown",
        number: 1011,
    },
    PortDefinition {
        service: "isis-bcast",
        number: 2043,
    },
    PortDefinition {
        service: "dls",
        number: 2047,
    },
    PortDefinition {
        service: "fw1-secureremote",
        number: 256,
    },
    PortDefinition {
        service: "nping-echo",
        number: 9929,
    },
    PortDefinition {
        service: "ncd-diag",
        number: 5998,
    },
    PortDefinition {
        service: "imsp",
        number: 406,
    },
    PortDefinition {
        service: "Elite",
        number: 31337,
    },
    PortDefinition {
        service: "coldfusion-auth",
        number: 44442,
    },
    PortDefinition {
        service: "spamassassin",
        number: 783,
    },
    PortDefinition {
        service: "unknown",
        number: 843,
    },
    PortDefinition {
        service: "isis",
        number: 2042,
    },
    PortDefinition {
        service: "cdfunc",
        number: 2045,
    },
    PortDefinition {
        service: "yo-main",
        number: 4040,
    },
    PortDefinition {
        service: "x9-icue",
        number: 1145,
    },
    PortDefinition {
        service: "x11",
        number: 6060,
    },
    PortDefinition {
        service: "x11",
        number: 6051,
    },
    PortDefinition {
        service: "wysdmc",
        number: 3916,
    },
    PortDefinition {
        service: "tungsten-https",
        number: 9443,
    },
    PortDefinition {
        service: "wso2esb-console",
        number: 9444,
    },
    PortDefinition {
        service: "westell-stats",
        number: 1875,
    },
    PortDefinition {
        service: "watchme-7272",
        number: 7272,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4252,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4200,
    },
    PortDefinition {
        service: "vmsvc",
        number: 7024,
    },
    PortDefinition {
        service: "veritas_pbx",
        number: 1556,
    },
    PortDefinition {
        service: "vnetd",
        number: 13724,
    },
    PortDefinition {
        service: "mxomss",
        number: 1141,
    },
    PortDefinition {
        service: "univ-appserver",
        number: 1233,
    },
    PortDefinition {
        service: "ultraseek-http",
        number: 8765,
    },
    PortDefinition {
        service: "trim",
        number: 1137,
    },
    PortDefinition {
        service: "thrp",
        number: 3963,
    },
    PortDefinition {
        service: "teamviewer",
        number: 5938,
    },
    PortDefinition {
        service: "sun-as-jpda",
        number: 9191,
    },
    PortDefinition {
        service: "sun-as-iiops-ca",
        number: 3808,
    },
    PortDefinition {
        service: "sun-as-jmxrmi",
        number: 8686,
    },
    PortDefinition {
        service: "starfish",
        number: 3981,
    },
    PortDefinition {
        service: "sso-service",
        number: 2710,
    },
    PortDefinition {
        service: "sse-app-config",
        number: 3852,
    },
    PortDefinition {
        service: "spw-dnspreload",
        number: 3849,
    },
    PortDefinition {
        service: "sops",
        number: 3944,
    },
    PortDefinition {
        service: "sscan",
        number: 3853,
    },
    PortDefinition {
        service: "nsesrvr",
        number: 9988,
    },
    PortDefinition {
        service: "sddp",
        number: 1163,
    },
    PortDefinition {
        service: "silverpeakcomm",
        number: 4164,
    },
    PortDefinition {
        service: "scp",
        number: 3820,
    },
    PortDefinition {
        service: "servicetags",
        number: 6481,
    },
    PortDefinition {
        service: "smap",
        number: 3731,
    },
    PortDefinition {
        service: "sdl-ets",
        number: 5081,
    },
    PortDefinition {
        service: "safetynetp",
        number: 40000,
    },
    PortDefinition {
        service: "sac",
        number: 8097,
    },
    PortDefinition {
        service: "rsip",
        number: 4555,
    },
    PortDefinition {
        service: "asap-tcp",
        number: 3863,
    },
    PortDefinition {
        service: "routematch",
        number: 1287,
    },
    PortDefinition {
        service: "rsqlserver",
        number: 4430,
    },
    PortDefinition {
        service: "raqmon-pdu",
        number: 7744,
    },
    PortDefinition {
        service: "radius",
        number: 1812,
    },
    PortDefinition {
        service: "qo-secure",
        number: 7913,
    },
    PortDefinition {
        service: "qsm-remote",
        number: 1166,
    },
    PortDefinition {
        service: "qsm-proxy",
        number: 1164,
    },
    PortDefinition {
        service: "qsm-gui",
        number: 1165,
    },
    PortDefinition {
        service: "qbdb",
        number: 8019,
    },
    PortDefinition {
        service: "qb-db-server",
        number: 10160,
    },
    PortDefinition {
        service: "playsta2-app",
        number: 4658,
    },
    PortDefinition {
        service: "owms",
        number: 7878,
    },
    PortDefinition {
        service: "opennl-voice",
        number: 1259,
    },
    PortDefinition {
        service: "obrpd",
        number: 1092,
    },
    PortDefinition {
        service: "opsession-srvr",
        number: 3304,
    },
    PortDefinition {
        service: "opsession-prxy",
        number: 3307,
    },
    PortDefinition {
        service: "oma-dcdocbs",
        number: 7278,
    },
    PortDefinition {
        service: "oem-agent",
        number: 3872,
    },
    PortDefinition {
        service: "octopus",
        number: 10008,
    },
    PortDefinition {
        service: "nitrogen",
        number: 7725,
    },
    PortDefinition {
        service: "networklenss",
        number: 3410,
    },
    PortDefinition {
        service: "netop-school",
        number: 1971,
    },
    PortDefinition {
        service: "nw-license",
        number: 3697,
    },
    PortDefinition {
        service: "nav-port",
        number: 3859,
    },
    PortDefinition {
        service: "must-p2p",
        number: 3514,
    },
    PortDefinition {
        service: "munin",
        number: 4949,
    },
    PortDefinition {
        service: "vrxpservman",
        number: 4147,
    },
    PortDefinition {
        service: "mevent",
        number: 7900,
    },
    PortDefinition {
        service: "mdns",
        number: 5353,
    },
    PortDefinition {
        service: "msr-plugin-port",
        number: 3931,
    },
    PortDefinition {
        service: "msi-cps-rm",
        number: 8675,
    },
    PortDefinition {
        service: "miva-mqs",
        number: 1277,
    },
    PortDefinition {
        service: "mqe-broker",
        number: 3957,
    },
    PortDefinition {
        service: "mpc-lifenet",
        number: 1213,
    },
    PortDefinition {
        service: "ms-olap3",
        number: 2382,
    },
    PortDefinition {
        service: "mshvlm",
        number: 6600,
    },
    PortDefinition {
        service: "lrs-paging",
        number: 3700,
    },
    PortDefinition {
        service: "lotusmtap",
        number: 3007,
    },
    PortDefinition {
        service: "lorica-in",
        number: 4080,
    },
    PortDefinition {
        service: "ltp-deepspace",
        number: 1113,
    },
    PortDefinition {
        service: "landmarks",
        number: 3969,
    },
    PortDefinition {
        service: "kvm-via-ip",
        number: 1132,
    },
    PortDefinition {
        service: "jtag-server",
        number: 1309,
    },
    PortDefinition {
        service: "itactionserver2",
        number: 7281,
    },
    PortDefinition {
        service: "item",
        number: 3848,
    },
    PortDefinition {
        service: "imoguia-port",
        number: 3907,
    },
    PortDefinition {
        service: "iconp",
        number: 3972,
    },
    PortDefinition {
        service: "ianywhere-dbns",
        number: 3968,
    },
    PortDefinition {
        service: "hpss-ndapi",
        number: 1217,
    },
    PortDefinition {
        service: "hpvmmdata",
        number: 1126,
    },
    PortDefinition {
        service: "hpvirtgrp",
        number: 5223,
    },
    PortDefinition {
        service: "ovsam-d-agent",
        number: 3870,
    },
    PortDefinition {
        service: "homeportal-web",
        number: 3941,
    },
    PortDefinition {
        service: "hiperscan-id",
        number: 8293,
    },
    PortDefinition {
        service: "h323hostcallsc",
        number: 1300,
    },
    PortDefinition {
        service: "h323gatestat",
        number: 1719,
    },
    PortDefinition {
        service: "h2250-annex-g",
        number: 2099,
    },
    PortDefinition {
        service: "gsmp",
        number: 6068,
    },
    PortDefinition {
        service: "gilatskysurfer",
        number: 3013,
    },
    PortDefinition {
        service: "gds_db",
        number: 3050,
    },
    PortDefinition {
        service: "fnet-remote-ui",
        number: 1174,
    },
    PortDefinition {
        service: "faxstfx-port",
        number: 3684,
    },
    PortDefinition {
        service: "eyetv",
        number: 2170,
    },
    PortDefinition {
        service: "sitewatch",
        number: 3792,
    },
    PortDefinition {
        service: "etebac5",
        number: 1216,
    },
    PortDefinition {
        service: "esri_sde",
        number: 5151,
    },
    PortDefinition {
        service: "empowerid",
        number: 7080,
    },
    PortDefinition {
        service: "easyengine",
        number: 22222,
    },
    PortDefinition {
        service: "oidsr",
        number: 4143,
    },
    PortDefinition {
        service: "diameters",
        number: 5868,
    },
    PortDefinition {
        service: "ddi-tcp-2",
        number: 8889,
    },
    PortDefinition {
        service: "dbisamserver2",
        number: 12006,
    },
    PortDefinition {
        service: "rmpp",
        number: 1121,
    },
    PortDefinition {
        service: "d2000kernel",
        number: 3119,
    },
    PortDefinition {
        service: "cfg-cloud",
        number: 8015,
    },
    PortDefinition {
        service: "cefd-vmp",
        number: 10023,
    },
    PortDefinition {
        service: "acp-policy",
        number: 3824,
    },
    PortDefinition {
        service: "resacommunity",
        number: 1154,
    },
    PortDefinition {
        service: "commtact-http",
        number: 20002,
    },
    PortDefinition {
        service: "ciphire-serv",
        number: 3888,
    },
    PortDefinition {
        service: "chimera-hwm",
        number: 4009,
    },
    PortDefinition {
        service: "csrpc",
        number: 5063,
    },
    PortDefinition {
        service: "cdbroker",
        number: 3376,
    },
    PortDefinition {
        service: "catchpole",
        number: 1185,
    },
    PortDefinition {
        service: "cajo-discovery",
        number: 1198,
    },
    PortDefinition {
        service: "caids-sensor",
        number: 1192,
    },
    PortDefinition {
        service: "intersys-cache",
        number: 1972,
    },
    PortDefinition {
        service: "casp",
        number: 1130,
    },
    PortDefinition {
        service: "bvtsonar",
        number: 1149,
    },
    PortDefinition {
        service: "bre",
        number: 4096,
    },
    PortDefinition {
        service: "boks",
        number: 6500,
    },
    PortDefinition {
        service: "blp4",
        number: 8294,
    },
    PortDefinition {
        service: "bv-is",
        number: 3990,
    },
    PortDefinition {
        service: "bv-agent",
        number: 3993,
    },
    PortDefinition {
        service: "ads-s",
        number: 8016,
    },
    PortDefinition {
        service: "an-pcp",
        number: 3846,
    },
    PortDefinition {
        service: "smauth-port",
        number: 3929,
    },
    PortDefinition {
        service: "alias",
        number: 1187,
    },
    PortDefinition {
        service: "alesquery",
        number: 5074,
    },
    PortDefinition {
        service: "amcs",
        number: 8766,
    },
    PortDefinition {
        service: "adobeserver-1",
        number: 1102,
    },
    PortDefinition {
        service: "acc-raid",
        number: 2800,
    },
    PortDefinition {
        service: "unknown",
        number: 9941,
    },
    PortDefinition {
        service: "unknown",
        number: 9914,
    },
    PortDefinition {
        service: "unknown",
        number: 9815,
    },
    PortDefinition {
        service: "unknown",
        number: 9673,
    },
    PortDefinition {
        service: "unknown",
        number: 9643,
    },
    PortDefinition {
        service: "unknown",
        number: 9621,
    },
    PortDefinition {
        service: "unknown",
        number: 9501,
    },
    PortDefinition {
        service: "unknown",
        number: 9409,
    },
    PortDefinition {
        service: "unknown",
        number: 9198,
    },
    PortDefinition {
        service: "unknown",
        number: 9197,
    },
    PortDefinition {
        service: "unknown",
        number: 9098,
    },
    PortDefinition {
        service: "unknown",
        number: 8996,
    },
    PortDefinition {
        service: "unknown",
        number: 8987,
    },
    PortDefinition {
        service: "unknown",
        number: 8877,
    },
    PortDefinition {
        service: "unknown",
        number: 8676,
    },
    PortDefinition {
        service: "unknown",
        number: 8648,
    },
    PortDefinition {
        service: "unknown",
        number: 8540,
    },
    PortDefinition {
        service: "unknown",
        number: 8481,
    },
    PortDefinition {
        service: "unknown",
        number: 8385,
    },
    PortDefinition {
        service: "unknown",
        number: 8189,
    },
    PortDefinition {
        service: "unknown",
        number: 8098,
    },
    PortDefinition {
        service: "unknown",
        number: 8095,
    },
    PortDefinition {
        service: "unknown",
        number: 8050,
    },
    PortDefinition {
        service: "unknown",
        number: 7929,
    },
    PortDefinition {
        service: "unknown",
        number: 7770,
    },
    PortDefinition {
        service: "unknown",
        number: 7749,
    },
    PortDefinition {
        service: "unknown",
        number: 7438,
    },
    PortDefinition {
        service: "unknown",
        number: 7241,
    },
    PortDefinition {
        service: "unknown",
        number: 7123,
    },
    PortDefinition {
        service: "unknown",
        number: 7051,
    },
    PortDefinition {
        service: "unknown",
        number: 7050,
    },
    PortDefinition {
        service: "unknown",
        number: 6896,
    },
    PortDefinition {
        service: "unknown",
        number: 6732,
    },
    PortDefinition {
        service: "unknown",
        number: 6711,
    },
    PortDefinition {
        service: "unknown",
        number: 65310,
    },
    PortDefinition {
        service: "unknown",
        number: 6520,
    },
    PortDefinition {
        service: "unknown",
        number: 6504,
    },
    PortDefinition {
        service: "unknown",
        number: 6247,
    },
    PortDefinition {
        service: "unknown",
        number: 6203,
    },
    PortDefinition {
        service: "unknown",
        number: 61613,
    },
    PortDefinition {
        service: "unknown",
        number: 60642,
    },
    PortDefinition {
        service: "unknown",
        number: 60146,
    },
    PortDefinition {
        service: "unknown",
        number: 60123,
    },
    PortDefinition {
        service: "unknown",
        number: 5981,
    },
    PortDefinition {
        service: "unknown",
        number: 5940,
    },
    PortDefinition {
        service: "unknown",
        number: 59202,
    },
    PortDefinition {
        service: "unknown",
        number: 59201,
    },
    PortDefinition {
        service: "unknown",
        number: 59200,
    },
    PortDefinition {
        service: "unknown",
        number: 5918,
    },
    PortDefinition {
        service: "unknown",
        number: 5914,
    },
    PortDefinition {
        service: "unknown",
        number: 59110,
    },
    PortDefinition {
        service: "unknown",
        number: 5909,
    },
    PortDefinition {
        service: "unknown",
        number: 5905,
    },
    PortDefinition {
        service: "unknown",
        number: 5899,
    },
    PortDefinition {
        service: "unknown",
        number: 58838,
    },
    PortDefinition {
        service: "unknown",
        number: 5869,
    },
    PortDefinition {
        service: "unknown",
        number: 58632,
    },
    PortDefinition {
        service: "unknown",
        number: 58630,
    },
    PortDefinition {
        service: "unknown",
        number: 5823,
    },
    PortDefinition {
        service: "unknown",
        number: 5818,
    },
    PortDefinition {
        service: "unknown",
        number: 5812,
    },
    PortDefinition {
        service: "unknown",
        number: 5807,
    },
    PortDefinition {
        service: "unknown",
        number: 58002,
    },
    PortDefinition {
        service: "unknown",
        number: 58001,
    },
    PortDefinition {
        service: "unknown",
        number: 57665,
    },
    PortDefinition {
        service: "unknown",
        number: 55576,
    },
    PortDefinition {
        service: "unknown",
        number: 55020,
    },
    PortDefinition {
        service: "unknown",
        number: 53535,
    },
    PortDefinition {
        service: "unknown",
        number: 5339,
    },
    PortDefinition {
        service: "unknown",
        number: 53314,
    },
    PortDefinition {
        service: "unknown",
        number: 53313,
    },
    PortDefinition {
        service: "unknown",
        number: 53211,
    },
    PortDefinition {
        service: "unknown",
        number: 52853,
    },
    PortDefinition {
        service: "unknown",
        number: 52851,
    },
    PortDefinition {
        service: "unknown",
        number: 52850,
    },
    PortDefinition {
        service: "unknown",
        number: 52849,
    },
    PortDefinition {
        service: "unknown",
        number: 52847,
    },
    PortDefinition {
        service: "unknown",
        number: 5279,
    },
    PortDefinition {
        service: "unknown",
        number: 52735,
    },
    PortDefinition {
        service: "unknown",
        number: 52710,
    },
    PortDefinition {
        service: "unknown",
        number: 52660,
    },
    PortDefinition {
        service: "unknown",
        number: 5242,
    },
    PortDefinition {
        service: "unknown",
        number: 5212,
    },
    PortDefinition {
        service: "unknown",
        number: 51413,
    },
    PortDefinition {
        service: "unknown",
        number: 51191,
    },
    PortDefinition {
        service: "unknown",
        number: 5040,
    },
    PortDefinition {
        service: "unknown",
        number: 50050,
    },
    PortDefinition {
        service: "unknown",
        number: 49401,
    },
    PortDefinition {
        service: "unknown",
        number: 49236,
    },
    PortDefinition {
        service: "unknown",
        number: 49195,
    },
    PortDefinition {
        service: "unknown",
        number: 49186,
    },
    PortDefinition {
        service: "unknown",
        number: 49171,
    },
    PortDefinition {
        service: "unknown",
        number: 49168,
    },
    PortDefinition {
        service: "unknown",
        number: 49164,
    },
    PortDefinition {
        service: "unknown",
        number: 4875,
    },
    PortDefinition {
        service: "unknown",
        number: 47544,
    },
    PortDefinition {
        service: "unknown",
        number: 46996,
    },
    PortDefinition {
        service: "unknown",
        number: 46200,
    },
    PortDefinition {
        service: "unknown",
        number: 44709,
    },
    PortDefinition {
        service: "unknown",
        number: 41523,
    },
    PortDefinition {
        service: "unknown",
        number: 41064,
    },
    PortDefinition {
        service: "unknown",
        number: 40811,
    },
    PortDefinition {
        service: "unknown",
        number: 3994,
    },
    PortDefinition {
        service: "unknown",
        number: 39659,
    },
    PortDefinition {
        service: "unknown",
        number: 39376,
    },
    PortDefinition {
        service: "unknown",
        number: 39136,
    },
    PortDefinition {
        service: "unknown",
        number: 38188,
    },
    PortDefinition {
        service: "unknown",
        number: 38185,
    },
    PortDefinition {
        service: "unknown",
        number: 37839,
    },
    PortDefinition {
        service: "unknown",
        number: 35513,
    },
    PortDefinition {
        service: "unknown",
        number: 33554,
    },
    PortDefinition {
        service: "unknown",
        number: 33453,
    },
    PortDefinition {
        service: "unknown",
        number: 32835,
    },
    PortDefinition {
        service: "unknown",
        number: 32822,
    },
    PortDefinition {
        service: "unknown",
        number: 32816,
    },
    PortDefinition {
        service: "unknown",
        number: 32803,
    },
    PortDefinition {
        service: "unknown",
        number: 32792,
    },
    PortDefinition {
        service: "unknown",
        number: 32791,
    },
    PortDefinition {
        service: "unknown",
        number: 30704,
    },
    PortDefinition {
        service: "unknown",
        number: 30005,
    },
    PortDefinition {
        service: "unknown",
        number: 29831,
    },
    PortDefinition {
        service: "unknown",
        number: 29672,
    },
    PortDefinition {
        service: "unknown",
        number: 28211,
    },
    PortDefinition {
        service: "unknown",
        number: 27357,
    },
    PortDefinition {
        service: "unknown",
        number: 26470,
    },
    PortDefinition {
        service: "unknown",
        number: 23796,
    },
    PortDefinition {
        service: "unknown",
        number: 23052,
    },
    PortDefinition {
        service: "unknown",
        number: 2196,
    },
    PortDefinition {
        service: "unknown",
        number: 21792,
    },
    PortDefinition {
        service: "unknown",
        number: 19900,
    },
    PortDefinition {
        service: "unknown",
        number: 18264,
    },
    PortDefinition {
        service: "unknown",
        number: 18018,
    },
    PortDefinition {
        service: "unknown",
        number: 17595,
    },
    PortDefinition {
        service: "unknown",
        number: 16851,
    },
    PortDefinition {
        service: "unknown",
        number: 16800,
    },
    PortDefinition {
        service: "unknown",
        number: 16705,
    },
    PortDefinition {
        service: "unknown",
        number: 15402,
    },
    PortDefinition {
        service: "unknown",
        number: 15001,
    },
    PortDefinition {
        service: "unknown",
        number: 12452,
    },
    PortDefinition {
        service: "unknown",
        number: 12380,
    },
    PortDefinition {
        service: "unknown",
        number: 12262,
    },
    PortDefinition {
        service: "unknown",
        number: 12215,
    },
    PortDefinition {
        service: "unknown",
        number: 12059,
    },
    PortDefinition {
        service: "unknown",
        number: 12021,
    },
    PortDefinition {
        service: "unknown",
        number: 10873,
    },
    PortDefinition {
        service: "unknown",
        number: 10058,
    },
    PortDefinition {
        service: "unknown",
        number: 10034,
    },
    PortDefinition {
        service: "unknown",
        number: 10022,
    },
    PortDefinition {
        service: "unknown",
        number: 10011,
    },
    PortDefinition {
        service: "tdaccess",
        number: 2910,
    },
    PortDefinition {
        service: "sixtrak",
        number: 1594,
    },
    PortDefinition {
        service: "sixnetudr",
        number: 1658,
    },
    PortDefinition {
        service: "simbaexpress",
        number: 1583,
    },
    PortDefinition {
        service: "sflm",
        number: 3162,
    },
    PortDefinition {
        service: "roboeda",
        number: 2920,
    },
    PortDefinition {
        service: "quake",
        number: 26000,
    },
    PortDefinition {
        service: "qip-login",
        number: 2366,
    },
    PortDefinition {
        service: "piranha1",
        number: 4600,
    },
    PortDefinition {
        service: "nsjtp-data",
        number: 1688,
    },
    PortDefinition {
        service: "novation",
        number: 1322,
    },
    PortDefinition {
        service: "nicetec-mgmt",
        number: 2557,
    },
    PortDefinition {
        service: "nicelink",
        number: 1095,
    },
    PortDefinition {
        service: "netopia-vo1",
        number: 1839,
    },
    PortDefinition {
        service: "netml",
        number: 2288,
    },
    PortDefinition {
        service: "murray",
        number: 1123,
    },
    PortDefinition {
        service: "mppolicy-v5",
        number: 5968,
    },
    PortDefinition {
        service: "micromuse-ncpw",
        number: 9600,
    },
    PortDefinition {
        service: "isbconference1",
        number: 1244,
    },
    PortDefinition {
        service: "invision",
        number: 1641,
    },
    PortDefinition {
        service: "ici",
        number: 2200,
    },
    PortDefinition {
        service: "ftranhc",
        number: 1105,
    },
    PortDefinition {
        service: "fg-sysupdate",
        number: 6550,
    },
    PortDefinition {
        service: "fcp-addr-srvr2",
        number: 5501,
    },
    PortDefinition {
        service: "ewall",
        number: 1328,
    },
    PortDefinition {
        service: "enpp",
        number: 2968,
    },
    PortDefinition {
        service: "enl-name",
        number: 1805,
    },
    PortDefinition {
        service: "elm-momentum",
        number: 1914,
    },
    PortDefinition {
        service: "drp",
        number: 1974,
    },
    PortDefinition {
        service: "diagd",
        number: 31727,
    },
    PortDefinition {
        service: "csms2",
        number: 3400,
    },
    PortDefinition {
        service: "ci3-software-1",
        number: 1301,
    },
    PortDefinition {
        service: "capioverlan",
        number: 1147,
    },
    PortDefinition {
        service: "caicci",
        number: 1721,
    },
    PortDefinition {
        service: "bvcontrol",
        number: 1236,
    },
    PortDefinition {
        service: "rtsclient",
        number: 2501,
    },
    PortDefinition {
        service: "ttyinfo",
        number: 2012,
    },
    PortDefinition {
        service: "radmind",
        number: 6222,
    },
    PortDefinition {
        service: "quicktime",
        number: 1220,
    },
    PortDefinition {
        service: "kpop",
        number: 1109,
    },
    PortDefinition {
        service: "bbn-mmc",
        number: 1347,
    },
    PortDefinition {
        service: "mbap",
        number: 502,
    },
    PortDefinition {
        service: "lmp",
        number: 701,
    },
    PortDefinition {
        service: "ivs-video",
        number: 2232,
    },
    PortDefinition {
        service: "ivsd",
        number: 2241,
    },
    PortDefinition {
        service: "hylafax",
        number: 4559,
    },
    PortDefinition {
        service: "entrust-ash",
        number: 710,
    },
    PortDefinition {
        service: "stel",
        number: 10005,
    },
    PortDefinition {
        service: "canna",
        number: 5680,
    },
    PortDefinition {
        service: "oob-ws-http",
        number: 623,
    },
    PortDefinition {
        service: "apex-edge",
        number: 913,
    },
    PortDefinition {
        service: "xaudio",
        number: 1103,
    },
    PortDefinition {
        service: "wpgs",
        number: 780,
    },
    PortDefinition {
        service: "unknown",
        number: 930,
    },
    PortDefinition {
        service: "unknown",
        number: 803,
    },
    PortDefinition {
        service: "unknown",
        number: 725,
    },
    PortDefinition {
        service: "msdp",
        number: 639,
    },
    PortDefinition {
        service: "uucp",
        number: 540,
    },
    PortDefinition {
        service: "iso-tsap",
        number: 102,
    },
    PortDefinition {
        service: "telelpathstart",
        number: 5010,
    },
    PortDefinition {
        service: "nerv",
        number: 1222,
    },
    PortDefinition {
        service: "rndc",
        number: 953,
    },
    PortDefinition {
        service: "privoxy",
        number: 8118,
    },
    PortDefinition {
        service: "issc",
        number: 9992,
    },
    PortDefinition {
        service: "ssserver",
        number: 1270,
    },
    PortDefinition {
        service: "nsw-fe",
        number: 27,
    },
    PortDefinition {
        service: "ntp",
        number: 123,
    },
    PortDefinition {
        service: "mfcobol",
        number: 86,
    },
    PortDefinition {
        service: "ddm-dfm",
        number: 447,
    },
    PortDefinition {
        service: "lsnr",
        number: 1158,
    },
    PortDefinition {
        service: "cvc_hostd",
        number: 442,
    },
    PortDefinition {
        service: "biimenu",
        number: 18000,
    },
    PortDefinition {
        service: "ariel1",
        number: 419,
    },
    PortDefinition {
        service: "unknown",
        number: 931,
    },
    PortDefinition {
        service: "unknown",
        number: 874,
    },
    PortDefinition {
        service: "unknown",
        number: 856,
    },
    PortDefinition {
        service: "unknown",
        number: 250,
    },
    PortDefinition {
        service: "tcpnethaspsrv",
        number: 475,
    },
    PortDefinition {
        service: "rimsl",
        number: 2044,
    },
    PortDefinition {
        service: "decvms-sysmgt",
        number: 441,
    },
    PortDefinition {
        service: "z39.50",
        number: 210,
    },
    PortDefinition {
        service: "X11:8",
        number: 6008,
    },
    PortDefinition {
        service: "afs3-vlserver",
        number: 7003,
    },
    PortDefinition {
        service: "vnc-http-3",
        number: 5803,
    },
    PortDefinition {
        service: "ufsd",
        number: 1008,
    },
    PortDefinition {
        service: "remotefs",
        number: 556,
    },
    PortDefinition {
        service: "RETS-or-BackupExec",
        number: 6103,
    },
    PortDefinition {
        service: "pkix-3-ca-ra",
        number: 829,
    },
    PortDefinition {
        service: "saprouter",
        number: 3299,
    },
    PortDefinition {
        service: "isi-gl",
        number: 55,
    },
    PortDefinition {
        service: "iris-xpc",
        number: 713,
    },
    PortDefinition {
        service: "3m-image-lm",
        number: 1550,
    },
    PortDefinition {
        service: "entrustmanager",
        number: 709,
    },
    PortDefinition {
        service: "dict",
        number: 2628,
    },
    PortDefinition {
        service: "cdc",
        number: 223,
    },
    PortDefinition {
        service: "slnp",
        number: 3025,
    },
    PortDefinition {
        service: "priv-term-l",
        number: 87,
    },
    PortDefinition {
        service: "priv-term",
        number: 57,
    },
    PortDefinition {
        service: "amidxtape",
        number: 10083,
    },
    PortDefinition {
        service: "sdlog",
        number: 5520,
    },
    PortDefinition {
        service: "unknown",
        number: 980,
    },
    PortDefinition {
        service: "unknown",
        number: 251,
    },
    PortDefinition {
        service: "unknown",
        number: 1013,
    },
    PortDefinition {
        service: "ms-sql2000",
        number: 9152,
    },
    PortDefinition {
        service: "lupa",
        number: 1212,
    },
    PortDefinition {
        service: "codasrv-se",
        number: 2433,
    },
    PortDefinition {
        service: "vpad",
        number: 1516,
    },
    PortDefinition {
        service: "texar",
        number: 333,
    },
    PortDefinition {
        service: "raid-cc",
        number: 2011,
    },
    PortDefinition {
        service: "ris-cm",
        number: 748,
    },
    PortDefinition {
        service: "editbench",
        number: 1350,
    },
    PortDefinition {
        service: "pdap-np",
        number: 1526,
    },
    PortDefinition {
        service: "ups-onlinet",
        number: 7010,
    },
    PortDefinition {
        service: "nessus",
        number: 1241,
    },
    PortDefinition {
        service: "locus-con",
        number: 127,
    },
    PortDefinition {
        service: "knet-cmp",
        number: 157,
    },
    PortDefinition {
        service: "imap3",
        number: 220,
    },
    PortDefinition {
        service: "equationbuilder",
        number: 1351,
    },
    PortDefinition {
        service: "dlswpn",
        number: 2067,
    },
    PortDefinition {
        service: "corba-iiop-ssl",
        number: 684,
    },
    PortDefinition {
        service: "priv-rje",
        number: 77,
    },
    PortDefinition {
        service: "msql",
        number: 4333,
    },
    PortDefinition {
        service: "acap",
        number: 674,
    },
    PortDefinition {
        service: "unknown",
        number: 943,
    },
    PortDefinition {
        service: "unknown",
        number: 904,
    },
    PortDefinition {
        service: "unknown",
        number: 840,
    },
    PortDefinition {
        service: "unknown",
        number: 825,
    },
    PortDefinition {
        service: "unknown",
        number: 792,
    },
    PortDefinition {
        service: "unknown",
        number: 732,
    },
    PortDefinition {
        service: "unknown",
        number: 1020,
    },
    PortDefinition {
        service: "unknown",
        number: 1006,
    },
    PortDefinition {
        service: "rmc",
        number: 657,
    },
    PortDefinition {
        service: "openvms-sysipc",
        number: 557,
    },
    PortDefinition {
        service: "npmp-local",
        number: 610,
    },
    PortDefinition {
        service: "laplink",
        number: 1547,
    },
    PortDefinition {
        service: "ibm-db2",
        number: 523,
    },
    PortDefinition {
        service: "xtreelic",
        number: 996,
    },
    PortDefinition {
        service: "ellpack",
        number: 2025,
    },
    PortDefinition {
        service: "xmlrpc-beep",
        number: 602,
    },
    PortDefinition {
        service: "vat",
        number: 3456,
    },
    PortDefinition {
        service: "twamp-control",
        number: 862,
    },
    PortDefinition {
        service: "ipcserver",
        number: 600,
    },
    PortDefinition {
        service: "extensisportfolio",
        number: 2903,
    },
    PortDefinition {
        service: "fw1-mc-fwmodule",
        number: 257,
    },
    PortDefinition {
        service: "rna-lm",
        number: 1522,
    },
    PortDefinition {
        service: "relief",
        number: 1353,
    },
    PortDefinition {
        service: "radmind",
        number: 6662,
    },
    PortDefinition {
        service: "busboy",
        number: 998,
    },
    PortDefinition {
        service: "mac-srvr-admin",
        number: 660,
    },
    PortDefinition {
        service: "netviewdm1",
        number: 729,
    },
    PortDefinition {
        service: "netviewdm2",
        number: 730,
    },
    PortDefinition {
        service: "netviewdm3",
        number: 731,
    },
    PortDefinition {
        service: "hp-managed-node",
        number: 782,
    },
    PortDefinition {
        service: "pegboard",
        number: 1357,
    },
    PortDefinition {
        service: "distccd",
        number: 3632,
    },
    PortDefinition {
        service: "sapeps",
        number: 3399,
    },
    PortDefinition {
        service: "arcserve",
        number: 6050,
    },
    PortDefinition {
        service: "ats",
        number: 2201,
    },
    PortDefinition {
        service: "unknown",
        number: 971,
    },
    PortDefinition {
        service: "unknown",
        number: 969,
    },
    PortDefinition {
        service: "unknown",
        number: 905,
    },
    PortDefinition {
        service: "unknown",
        number: 846,
    },
    PortDefinition {
        service: "unknown",
        number: 839,
    },
    PortDefinition {
        service: "unknown",
        number: 823,
    },
    PortDefinition {
        service: "unknown",
        number: 822,
    },
    PortDefinition {
        service: "unknown",
        number: 795,
    },
    PortDefinition {
        service: "unknown",
        number: 790,
    },
    PortDefinition {
        service: "unknown",
        number: 778,
    },
    PortDefinition {
        service: "unknown",
        number: 757,
    },
    PortDefinition {
        service: "unknown",
        number: 659,
    },
    PortDefinition {
        service: "unknown",
        number: 225,
    },
    PortDefinition {
        service: "unknown",
        number: 1015,
    },
    PortDefinition {
        service: "unknown",
        number: 1014,
    },
    PortDefinition {
        service: "unknown",
        number: 1012,
    },
    PortDefinition {
        service: "tinc",
        number: 655,
    },
    PortDefinition {
        service: "concert",
        number: 786,
    },
    PortDefinition {
        service: "xmail-ctrl",
        number: 6017,
    },
    PortDefinition {
        service: "irc",
        number: 6670,
    },
    PortDefinition {
        service: "vatp",
        number: 690,
    },
    PortDefinition {
        service: "unidata-ldm",
        number: 388,
    },
    PortDefinition {
        service: "tinyfw",
        number: 44334,
    },
    PortDefinition {
        service: "krb_prop",
        number: 754,
    },
    PortDefinition {
        service: "telelpathattack",
        number: 5011,
    },
    PortDefinition {
        service: "linuxconf",
        number: 98,
    },
    PortDefinition {
        service: "rmt",
        number: 411,
    },
    PortDefinition {
        service: "orasrv",
        number: 1525,
    },
    PortDefinition {
        service: "remoteanything",
        number: 3999,
    },
    PortDefinition {
        service: "netcp",
        number: 740,
    },
    PortDefinition {
        service: "netbus",
        number: 12346,
    },
    PortDefinition {
        service: "mbap-s",
        number: 802,
    },
    PortDefinition {
        service: "waste",
        number: 1337,
    },
    PortDefinition {
        service: "supfiledbg",
        number: 1127,
    },
    PortDefinition {
        service: "kip",
        number: 2112,
    },
    PortDefinition {
        service: "ibm-mqseries",
        number: 1414,
    },
    PortDefinition {
        service: "zebrasrv",
        number: 2600,
    },
    PortDefinition {
        service: "escp-ip",
        number: 621,
    },
    PortDefinition {
        service: "urm",
        number: 606,
    },
    PortDefinition {
        service: "priv-file",
        number: 59,
    },
    PortDefinition {
        service: "unknown",
        number: 928,
    },
    PortDefinition {
        service: "unknown",
        number: 924,
    },
    PortDefinition {
        service: "unknown",
        number: 922,
    },
    PortDefinition {
        service: "unknown",
        number: 921,
    },
    PortDefinition {
        service: "unknown",
        number: 918,
    },
    PortDefinition {
        service: "unknown",
        number: 878,
    },
    PortDefinition {
        service: "unknown",
        number: 864,
    },
    PortDefinition {
        service: "unknown",
        number: 859,
    },
    PortDefinition {
        service: "unknown",
        number: 806,
    },
    PortDefinition {
        service: "unknown",
        number: 805,
    },
    PortDefinition {
        service: "unknown",
        number: 728,
    },
    PortDefinition {
        service: "unknown",
        number: 252,
    },
    PortDefinition {
        service: "unknown",
        number: 1005,
    },
    PortDefinition {
        service: "unknown",
        number: 1004,
    },
    PortDefinition {
        service: "repcmd",
        number: 641,
    },
    PortDefinition {
        service: "nlogin",
        number: 758,
    },
    PortDefinition {
        service: "meregister",
        number: 669,
    },
    PortDefinition {
        service: "landesk-cba",
        number: 38037,
    },
    PortDefinition {
        service: "iris-lwz",
        number: 715,
    },
    PortDefinition {
        service: "innosys-acl",
        number: 1413,
    },
    PortDefinition {
        service: "zephyr-hm",
        number: 2104,
    },
    PortDefinition {
        service: "zented",
        number: 1229,
    },
    PortDefinition {
        service: "tapeware",
        number: 3817,
    },
    PortDefinition {
        service: "xnm-ssl",
        number: 3220,
    },
    PortDefinition {
        service: "xic",
        number: 6115,
    },
    PortDefinition {
        service: "xecp-node",
        number: 3940,
    },
    PortDefinition {
        service: "x11",
        number: 6063,
    },
    PortDefinition {
        service: "x11",
        number: 6062,
    },
    PortDefinition {
        service: "x11",
        number: 6055,
    },
    PortDefinition {
        service: "x11",
        number: 6052,
    },
    PortDefinition {
        service: "x11",
        number: 6030,
    },
    PortDefinition {
        service: "x11",
        number: 6021,
    },
    PortDefinition {
        service: "x11",
        number: 6015,
    },
    PortDefinition {
        service: "x11",
        number: 6010,
    },
    PortDefinition {
        service: "wrs_registry",
        number: 2340,
    },
    PortDefinition {
        service: "wpl-analytics",
        number: 8006,
    },
    PortDefinition {
        service: "oirtgsvc",
        number: 4141,
    },
    PortDefinition {
        service: "wlanauth",
        number: 3810,
    },
    PortDefinition {
        service: "winddlb",
        number: 1565,
    },
    PortDefinition {
        service: "webmail-2",
        number: 3511,
    },
    PortDefinition {
        service: "wsmans",
        number: 5986,
    },
    PortDefinition {
        service: "wsman",
        number: 5985,
    },
    PortDefinition {
        service: "wg-endpt-comms",
        number: 33000,
    },
    PortDefinition {
        service: "watchdog-nt",
        number: 2723,
    },
    PortDefinition {
        service: "wap-wsp-s",
        number: 9202,
    },
    PortDefinition {
        service: "wap-push-https",
        number: 4036,
    },
    PortDefinition {
        service: "wap-push-http",
        number: 4035,
    },
    PortDefinition {
        service: "wanscaler",
        number: 2312,
    },
    PortDefinition {
        service: "vxcrnbuport",
        number: 3652,
    },
    PortDefinition {
        service: "vs-server",
        number: 3280,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4243,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4298,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4297,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4294,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4262,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4234,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4220,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4206,
    },
    PortDefinition {
        service: "vocaltec-wconf",
        number: 22555,
    },
    PortDefinition {
        service: "vrace",
        number: 9300,
    },
    PortDefinition {
        service: "virprot-lm",
        number: 7121,
    },
    PortDefinition {
        service: "videte-cipc",
        number: 1927,
    },
    PortDefinition {
        service: "vop",
        number: 4433,
    },
    PortDefinition {
        service: "vtsas",
        number: 5070,
    },
    PortDefinition {
        service: "veritas-ucl",
        number: 2148,
    },
    PortDefinition {
        service: "vchat",
        number: 1168,
    },
    PortDefinition {
        service: "visweather",
        number: 9979,
    },
    PortDefinition {
        service: "usicontentpush",
        number: 7998,
    },
    PortDefinition {
        service: "updog",
        number: 4414,
    },
    PortDefinition {
        service: "unisys-lm",
        number: 1823,
    },
    PortDefinition {
        service: "tsp",
        number: 3653,
    },
    PortDefinition {
        service: "tgp",
        number: 1223,
    },
    PortDefinition {
        service: "trivnet2",
        number: 8201,
    },
    PortDefinition {
        service: "tritium-can",
        number: 4876,
    },
    PortDefinition {
        service: "triomotion",
        number: 3240,
    },
    PortDefinition {
        service: "travsoft-ipx-t",
        number: 2644,
    },
    PortDefinition {
        service: "trap",
        number: 4020,
    },
    PortDefinition {
        service: "topovista-data",
        number: 3906,
    },
    PortDefinition {
        service: "topx",
        number: 2436,
    },
    PortDefinition {
        service: "tolteces",
        number: 4375,
    },
    PortDefinition {
        service: "tnp1-port",
        number: 4024,
    },
    PortDefinition {
        service: "tmosms1",
        number: 5581,
    },
    PortDefinition {
        service: "tmosms0",
        number: 5580,
    },
    PortDefinition {
        service: "client-wakeup",
        number: 9694,
    },
    PortDefinition {
        service: "tl1-raw-ssl",
        number: 6251,
    },
    PortDefinition {
        service: "swx",
        number: 7345,
    },
    PortDefinition {
        service: "swx",
        number: 7325,
    },
    PortDefinition {
        service: "swx",
        number: 7320,
    },
    PortDefinition {
        service: "swx",
        number: 7300,
    },
    PortDefinition {
        service: "pcmk-remote",
        number: 3121,
    },
    PortDefinition {
        service: "apsolab-tags",
        number: 5473,
    },
    PortDefinition {
        service: "apsolab-data",
        number: 5475,
    },
    PortDefinition {
        service: "trap-daemon",
        number: 3600,
    },
    PortDefinition {
        service: "tig",
        number: 3943,
    },
    PortDefinition {
        service: "lutap",
        number: 4912,
    },
    PortDefinition {
        service: "tdmoip",
        number: 2142,
    },
    PortDefinition {
        service: "tcoregagent",
        number: 1976,
    },
    PortDefinition {
        service: "tcoflashagent",
        number: 1975,
    },
    PortDefinition {
        service: "targus-getdata2",
        number: 5202,
    },
    PortDefinition {
        service: "targus-getdata1",
        number: 5201,
    },
    PortDefinition {
        service: "talarian-mcast2",
        number: 4016,
    },
    PortDefinition {
        service: "taep-as-svc",
        number: 5111,
    },
    PortDefinition {
        service: "sype-transport",
        number: 9911,
    },
    PortDefinition {
        service: "netapp-sync",
        number: 10006,
    },
    PortDefinition {
        service: "symb-sb-port",
        number: 3923,
    },
    PortDefinition {
        service: "syam-webserver",
        number: 3930,
    },
    PortDefinition {
        service: "sweetware-apps",
        number: 1221,
    },
    PortDefinition {
        service: "svnetworks",
        number: 2973,
    },
    PortDefinition {
        service: "surfcontrolcpa",
        number: 3909,
    },
    PortDefinition {
        service: "spt-automation",
        number: 5814,
    },
    PortDefinition {
        service: "sua",
        number: 14001,
    },
    PortDefinition {
        service: "stm_pproc",
        number: 3080,
    },
    PortDefinition {
        service: "stat-cc",
        number: 4158,
    },
    PortDefinition {
        service: "starquiz-port",
        number: 3526,
    },
    PortDefinition {
        service: "mtp",
        number: 1911,
    },
    PortDefinition {
        service: "stanag-5066",
        number: 5066,
    },
    PortDefinition {
        service: "sso-control",
        number: 2711,
    },
    PortDefinition {
        service: "ssmc",
        number: 2187,
    },
    PortDefinition {
        service: "isrp-port",
        number: 3788,
    },
    PortDefinition {
        service: "spw-dialer",
        number: 3796,
    },
    PortDefinition {
        service: "sor-update",
        number: 3922,
    },
    PortDefinition {
        service: "mib-streaming",
        number: 2292,
    },
    PortDefinition {
        service: "sun-sea-port",
        number: 16161,
    },
    PortDefinition {
        service: "slslavemon",
        number: 3102,
    },
    PortDefinition {
        service: "socp-t",
        number: 4881,
    },
    PortDefinition {
        service: "smwan",
        number: 3979,
    },
    PortDefinition {
        service: "smile",
        number: 3670,
    },
    PortDefinition {
        service: "smcluster",
        number: 4174,
    },
    PortDefinition {
        service: "slim-devices",
        number: 3483,
    },
    PortDefinition {
        service: "sitaradir",
        number: 2631,
    },
    PortDefinition {
        service: "sslp",
        number: 1750,
    },
    PortDefinition {
        service: "sdo-ssh",
        number: 3897,
    },
    PortDefinition {
        service: "silhouette",
        number: 7500,
    },
    PortDefinition {
        service: "sgi-eventmond",
        number: 5553,
    },
    PortDefinition {
        service: "sgi-esphttp",
        number: 5554,
    },
    PortDefinition {
        service: "sapv1",
        number: 9875,
    },
    PortDefinition {
        service: "deploymentmap",
        number: 4570,
    },
    PortDefinition {
        service: "sasp",
        number: 3860,
    },
    PortDefinition {
        service: "sentinel-ent",
        number: 3712,
    },
    PortDefinition {
        service: "senomix01",
        number: 8052,
    },
    PortDefinition {
        service: "radsec",
        number: 2083,
    },
    PortDefinition {
        service: "secure-mqtt",
        number: 8883,
    },
    PortDefinition {
        service: "mmcals",
        number: 2271,
    },
    PortDefinition {
        service: "sixid",
        number: 4606,
    },
    PortDefinition {
        service: "seagull-ais",
        number: 1208,
    },
    PortDefinition {
        service: "sdt-lmd",
        number: 3319,
    },
    PortDefinition {
        service: "sdp-portmapper",
        number: 3935,
    },
    PortDefinition {
        service: "ssdispatch",
        number: 3430,
    },
    PortDefinition {
        service: "scanstat-1",
        number: 1215,
    },
    PortDefinition {
        service: "sbi-agent",
        number: 3962,
    },
    PortDefinition {
        service: "satvid-datalnk",
        number: 3368,
    },
    PortDefinition {
        service: "sasggprs",
        number: 3964,
    },
    PortDefinition {
        service: "saphostctrl",
        number: 1128,
    },
    PortDefinition {
        service: "farenet",
        number: 5557,
    },
    PortDefinition {
        service: "samsung-unidex",
        number: 4010,
    },
    PortDefinition {
        service: "sec-t4net-srv",
        number: 9400,
    },
    PortDefinition {
        service: "slp",
        number: 1605,
    },
    PortDefinition {
        service: "sah-lm",
        number: 3291,
    },
    PortDefinition {
        service: "rtps-discovery",
        number: 7400,
    },
    PortDefinition {
        service: "avt-profile-2",
        number: 5005,
    },
    PortDefinition {
        service: "rsvp-encap-2",
        number: 1699,
    },
    PortDefinition {
        service: "rsf-1",
        number: 1195,
    },
    PortDefinition {
        service: "rlm",
        number: 5053,
    },
    PortDefinition {
        service: "rap-ip",
        number: 3813,
    },
    PortDefinition {
        service: "registrar",
        number: 1712,
    },
    PortDefinition {
        service: "exlm-agent",
        number: 3002,
    },
    PortDefinition {
        service: "rtraceroute",
        number: 3765,
    },
    PortDefinition {
        service: "wsmlb",
        number: 3806,
    },
    PortDefinition {
        service: "recvr-rc",
        number: 43000,
    },
    PortDefinition {
        service: "worldwire",
        number: 2371,
    },
    PortDefinition {
        service: "raven-rmp",
        number: 3532,
    },
    PortDefinition {
        service: "radius-dynauth",
        number: 3799,
    },
    PortDefinition {
        service: "quickbooksrds",
        number: 3790,
    },
    PortDefinition {
        service: "quasar-server",
        number: 3599,
    },
    PortDefinition {
        service: "qtms-bootstrap",
        number: 3850,
    },
    PortDefinition {
        service: "qsnet-workst",
        number: 4355,
    },
    PortDefinition {
        service: "qsnet-nucl",
        number: 4358,
    },
    PortDefinition {
        service: "qsnet-cond",
        number: 4357,
    },
    PortDefinition {
        service: "qsnet-assist",
        number: 4356,
    },
    PortDefinition {
        service: "pyrrho",
        number: 5433,
    },
    PortDefinition {
        service: "netboot-pxe",
        number: 3928,
    },
    PortDefinition {
        service: "pulseaudio",
        number: 4713,
    },
    PortDefinition {
        service: "psi-ptt",
        number: 4374,
    },
    PortDefinition {
        service: "proaxess",
        number: 3961,
    },
    PortDefinition {
        service: "paragent",
        number: 9022,
    },
    PortDefinition {
        service: "printer_agent",
        number: 3396,
    },
    PortDefinition {
        service: "prnstatus",
        number: 3911,
    },
    PortDefinition {
        service: "zen-pawn",
        number: 7628,
    },
    PortDefinition {
        service: "tick-port",
        number: 3200,
    },
    PortDefinition {
        service: "predatar-comms",
        number: 1753,
    },
    PortDefinition {
        service: "ppsms",
        number: 3967,
    },
    PortDefinition {
        service: "ppcontrol",
        number: 2505,
    },
    PortDefinition {
        service: "nbt-pc",
        number: 5133,
    },
    PortDefinition {
        service: "ps-ams",
        number: 3658,
    },
    PortDefinition {
        service: "pim-port",
        number: 8471,
    },
    PortDefinition {
        service: "pdps",
        number: 1314,
    },
    PortDefinition {
        service: "pclemultimedia",
        number: 2558,
    },
    PortDefinition {
        service: "patrol-ism",
        number: 6161,
    },
    PortDefinition {
        service: "partimage",
        number: 4025,
    },
    PortDefinition {
        service: "ptk-alink",
        number: 3089,
    },
    PortDefinition {
        service: "panagolin-ident",
        number: 9021,
    },
    PortDefinition {
        service: "pago-services1",
        number: 30001,
    },
    PortDefinition {
        service: "otv",
        number: 8472,
    },
    PortDefinition {
        service: "onpsocket",
        number: 5014,
    },
    PortDefinition {
        service: "osm-appsrvr",
        number: 9990,
    },
    PortDefinition {
        service: "oracle-oms",
        number: 1159,
    },
    PortDefinition {
        service: "iascontrol",
        number: 1157,
    },
    PortDefinition {
        service: "odsi",
        number: 1308,
    },
    PortDefinition {
        service: "omhs",
        number: 5723,
    },
    PortDefinition {
        service: "ov-nnm-websrv",
        number: 3443,
    },
    PortDefinition {
        service: "omscontact",
        number: 4161,
    },
    PortDefinition {
        service: "omnivision",
        number: 1135,
    },
    PortDefinition {
        service: "oma-mlp-s",
        number: 9211,
    },
    PortDefinition {
        service: "oma-mlp",
        number: 9210,
    },
    PortDefinition {
        service: "omasgport",
        number: 4090,
    },
    PortDefinition {
        service: "office-tools",
        number: 7789,
    },
    PortDefinition {
        service: "odette-ftps",
        number: 6619,
    },
    PortDefinition {
        service: "odbcpathway",
        number: 9628,
    },
    PortDefinition {
        service: "nupaper-ss",
        number: 12121,
    },
    PortDefinition {
        service: "nssagentmgr",
        number: 4454,
    },
    PortDefinition {
        service: "npds-tracker",
        number: 3680,
    },
    PortDefinition {
        service: "nowcontact",
        number: 3167,
    },
    PortDefinition {
        service: "nimaux",
        number: 3902,
    },
    PortDefinition {
        service: "nimsh",
        number: 3901,
    },
    PortDefinition {
        service: "ndsconnect",
        number: 3890,
    },
    PortDefinition {
        service: "nhci",
        number: 3842,
    },
    PortDefinition {
        service: "newbay-snc-mc",
        number: 16900,
    },
    PortDefinition {
        service: "netxms-agent",
        number: 4700,
    },
    PortDefinition {
        service: "nst",
        number: 4687,
    },
    PortDefinition {
        service: "nod-provider",
        number: 8980,
    },
    PortDefinition {
        service: "netmagic",
        number: 1196,
    },
    PortDefinition {
        service: "nacagent",
        number: 4407,
    },
    PortDefinition {
        service: "galileolog",
        number: 3520,
    },
    PortDefinition {
        service: "nsp",
        number: 5012,
    },
    PortDefinition {
        service: "neto-wol-server",
        number: 3812,
    },
    PortDefinition {
        service: "netiq-endpt",
        number: 10115,
    },
    PortDefinition {
        service: "netbill-auth",
        number: 1615,
    },
    PortDefinition {
        service: "netscript",
        number: 4118,
    },
    PortDefinition {
        service: "netaspi",
        number: 2902,
    },
    PortDefinition {
        service: "ncdmirroring",
        number: 2706,
    },
    PortDefinition {
        service: "nbx-ser",
        number: 2095,
    },
    PortDefinition {
        service: "nbx-dir",
        number: 2096,
    },
    PortDefinition {
        service: "nati-vi-server",
        number: 3363,
    },
    PortDefinition {
        service: "ctsd",
        number: 5137,
    },
    PortDefinition {
        service: "myblast",
        number: 3795,
    },
    PortDefinition {
        service: "mxi",
        number: 8005,
    },
    PortDefinition {
        service: "mvs-capacity",
        number: 10007,
    },
    PortDefinition {
        service: "must-backplane",
        number: 3515,
    },
    PortDefinition {
        service: "mcreport",
        number: 8003,
    },
    PortDefinition {
        service: "msfw-control",
        number: 3847,
    },
    PortDefinition {
        service: "lsp-ping",
        number: 3503,
    },
    PortDefinition {
        service: "movaz-ssc",
        number: 5252,
    },
    PortDefinition {
        service: "mongod",
        number: 27017,
    },
    PortDefinition {
        service: "mnp-exchange",
        number: 2197,
    },
    PortDefinition {
        service: "minirem",
        number: 4120,
    },
    PortDefinition {
        service: "mc-client",
        number: 1180,
    },
    PortDefinition {
        service: "msdfsr",
        number: 5722,
    },
    PortDefinition {
        service: "aplx",
        number: 1134,
    },
    PortDefinition {
        service: "mqtt",
        number: 1883,
    },
    PortDefinition {
        service: "mesavistaco",
        number: 1249,
    },
    PortDefinition {
        service: "mcns-tel-ret",
        number: 3311,
    },
    PortDefinition {
        service: "mkm-discovery",
        number: 3837,
    },
    PortDefinition {
        service: "dvr-esm",
        number: 2804,
    },
    PortDefinition {
        service: "mtcevrunqman",
        number: 4558,
    },
    PortDefinition {
        service: "sieve",
        number: 4190,
    },
    PortDefinition {
        service: "lsi-raid-mgmt",
        number: 2463,
    },
    PortDefinition {
        service: "ssslog-mgr",
        number: 1204,
    },
    PortDefinition {
        service: "lms",
        number: 4056,
    },
    PortDefinition {
        service: "llsurfup-https",
        number: 1184,
    },
    PortDefinition {
        service: "litecoin",
        number: 19333,
    },
    PortDefinition {
        service: "litecoin",
        number: 9333,
    },
    PortDefinition {
        service: "listcrt-port",
        number: 3913,
    },
    PortDefinition {
        service: "lispworks-orb",
        number: 3672,
    },
    PortDefinition {
        service: "lisp-cons",
        number: 4342,
    },
    PortDefinition {
        service: "lmcs",
        number: 4877,
    },
    PortDefinition {
        service: "emprise-lsc",
        number: 3586,
    },
    PortDefinition {
        service: "libelle",
        number: 8282,
    },
    PortDefinition {
        service: "lecroy-vicp",
        number: 1861,
    },
    PortDefinition {
        service: "lofr-lm",
        number: 1752,
    },
    PortDefinition {
        service: "ldgateway",
        number: 9592,
    },
    PortDefinition {
        service: "l2f",
        number: 1701,
    },
    PortDefinition {
        service: "konspire2b",
        number: 6085,
    },
    PortDefinition {
        service: "kme-trap-port",
        number: 2081,
    },
    PortDefinition {
        service: "kingfisher",
        number: 4058,
    },
    PortDefinition {
        service: "kdm",
        number: 2115,
    },
    PortDefinition {
        service: "jmb-cds1",
        number: 8900,
    },
    PortDefinition {
        service: "jaxer-manager",
        number: 4328,
    },
    PortDefinition {
        service: "jmact6",
        number: 2958,
    },
    PortDefinition {
        service: "jmact5",
        number: 2957,
    },
    PortDefinition {
        service: "iwg1",
        number: 7071,
    },
    PortDefinition {
        service: "itv-control",
        number: 3899,
    },
    PortDefinition {
        service: "ito-e-gui",
        number: 2531,
    },
    PortDefinition {
        service: "itinternet",
        number: 2691,
    },
    PortDefinition {
        service: "ita-manager",
        number: 5052,
    },
    PortDefinition {
        service: "ismc",
        number: 1638,
    },
    PortDefinition {
        service: "softaudit",
        number: 3419,
    },
    PortDefinition {
        service: "isg-uda-server",
        number: 2551,
    },
    PortDefinition {
        service: "ip-qsig",
        number: 4029,
    },
    PortDefinition {
        service: "int-rcv-cntrl",
        number: 3603,
    },
    PortDefinition {
        service: "ischat",
        number: 1336,
    },
    PortDefinition {
        service: "infowave",
        number: 2082,
    },
    PortDefinition {
        service: "imyx",
        number: 1143,
    },
    PortDefinition {
        service: "infiniswitchcl",
        number: 3602,
    },
    PortDefinition {
        service: "indigo-server",
        number: 1176,
    },
    PortDefinition {
        service: "igo-incognito",
        number: 4100,
    },
    PortDefinition {
        service: "ifsf-hb-port",
        number: 3486,
    },
    PortDefinition {
        service: "iconstructsrv",
        number: 6077,
    },
    PortDefinition {
        service: "iims",
        number: 4800,
    },
    PortDefinition {
        service: "icg-swp",
        number: 2062,
    },
    PortDefinition {
        service: "can-nds",
        number: 1918,
    },
    PortDefinition {
        service: "entextnetwk",
        number: 12001,
    },
    PortDefinition {
        service: "entexthigh",
        number: 12002,
    },
    PortDefinition {
        service: "aurora",
        number: 9084,
    },
    PortDefinition {
        service: "iba-cfg",
        number: 7072,
    },
    PortDefinition {
        service: "iascontrol-oms",
        number: 1156,
    },
    PortDefinition {
        service: "iapp",
        number: 2313,
    },
    PortDefinition {
        service: "i3-sessionmgr",
        number: 3952,
    },
    PortDefinition {
        service: "hfcs-manager",
        number: 4999,
    },
    PortDefinition {
        service: "htuilsrv",
        number: 5023,
    },
    PortDefinition {
        service: "mongod",
        number: 28017,
    },
    PortDefinition {
        service: "mongod",
        number: 27019,
    },
    PortDefinition {
        service: "mongod",
        number: 27018,
    },
    PortDefinition {
        service: "event-port",
        number: 2069,
    },
    PortDefinition {
        service: "hri-port",
        number: 3439,
    },
    PortDefinition {
        service: "hrd-ncs",
        number: 6324,
    },
    PortDefinition {
        service: "hp-webadmin",
        number: 1188,
    },
    PortDefinition {
        service: "hpvmmagent",
        number: 1125,
    },
    PortDefinition {
        service: "hppronetman",
        number: 3908,
    },
    PortDefinition {
        service: "ovbus",
        number: 7501,
    },
    PortDefinition {
        service: "hncp-dtls-port",
        number: 8232,
    },
    PortDefinition {
        service: "hks-lm",
        number: 1722,
    },
    PortDefinition {
        service: "hippad",
        number: 2988,
    },
    PortDefinition {
        service: "hip-nat-t",
        number: 10500,
    },
    PortDefinition {
        service: "hhb-gateway",
        number: 1136,
    },
    PortDefinition {
        service: "health-trap",
        number: 1162,
    },
    PortDefinition {
        service: "abb-hw",
        number: 10020,
    },
    PortDefinition {
        service: "gsidcap",
        number: 22128,
    },
    PortDefinition {
        service: "groove-dpp",
        number: 1211,
    },
    PortDefinition {
        service: "gf",
        number: 3530,
    },
    PortDefinition {
        service: "ghvpn",
        number: 12009,
    },
    PortDefinition {
        service: "golem",
        number: 9005,
    },
    PortDefinition {
        service: "goahead-fldup",
        number: 3057,
    },
    PortDefinition {
        service: "gvcp",
        number: 3956,
    },
    PortDefinition {
        service: "gpfs",
        number: 1191,
    },
    PortDefinition {
        service: "nvmsgd",
        number: 3519,
    },
    PortDefinition {
        service: "galaxy-network",
        number: 5235,
    },
    PortDefinition {
        service: "fuscript",
        number: 1144,
    },
    PortDefinition {
        service: "fmp",
        number: 4745,
    },
    PortDefinition {
        service: "fjicl-tep-a",
        number: 1901,
    },
    PortDefinition {
        service: "fhsp",
        number: 1807,
    },
    PortDefinition {
        service: "fjitsuappmgr",
        number: 2425,
    },
    PortDefinition {
        service: "fis",
        number: 5912,
    },
    PortDefinition {
        service: "flamenco-proxy",
        number: 3210,
    },
    PortDefinition {
        service: "filenet-powsrm",
        number: 32767,
    },
    PortDefinition {
        service: "fmwp",
        number: 5015,
    },
    PortDefinition {
        service: "fmpro-v6",
        number: 5013,
    },
    PortDefinition {
        service: "ff-lr-port",
        number: 3622,
    },
    PortDefinition {
        service: "fazzt-admin",
        number: 4039,
    },
    PortDefinition {
        service: "ezmeeting-2",
        number: 10101,
    },
    PortDefinition {
        service: "enfs",
        number: 5233,
    },
    PortDefinition {
        service: "sde-discovery",
        number: 5152,
    },
    PortDefinition {
        service: "eisp",
        number: 3983,
    },
    PortDefinition {
        service: "eis",
        number: 3982,
    },
    PortDefinition {
        service: "erunbook_agent",
        number: 9616,
    },
    PortDefinition {
        service: "epmd",
        number: 4369,
    },
    PortDefinition {
        service: "e-woa",
        number: 3728,
    },
    PortDefinition {
        service: "ep-nsp",
        number: 3621,
    },
    PortDefinition {
        service: "eapsp",
        number: 2291,
    },
    PortDefinition {
        service: "ev-services",
        number: 5114,
    },
    PortDefinition {
        service: "elcn",
        number: 7101,
    },
    PortDefinition {
        service: "eli",
        number: 2087,
    },
    PortDefinition {
        service: "eenet",
        number: 5234,
    },
    PortDefinition {
        service: "edb-server1",
        number: 1635,
    },
    PortDefinition {
        service: "ecolor-imager",
        number: 3263,
    },
    PortDefinition {
        service: "e-builder",
        number: 4121,
    },
    PortDefinition {
        service: "mtsserver",
        number: 4602,
    },
    PortDefinition {
        service: "efi-mg",
        number: 2224,
    },
    PortDefinition {
        service: "els",
        number: 1315,
    },
    PortDefinition {
        service: "drip",
        number: 3949,
    },
    PortDefinition {
        service: "dddp",
        number: 9131,
    },
    PortDefinition {
        service: "dyna-access",
        number: 3310,
    },
    PortDefinition {
        service: "dvbservdsc",
        number: 3937,
    },
    PortDefinition {
        service: "dtv-chan-req",
        number: 2253,
    },
    PortDefinition {
        service: "msdts1",
        number: 3882,
    },
    PortDefinition {
        service: "dvapps",
        number: 3831,
    },
    PortDefinition {
        service: "docker",
        number: 2376,
    },
    PortDefinition {
        service: "docker",
        number: 2375,
    },
    PortDefinition {
        service: "dl_agent",
        number: 3876,
    },
    PortDefinition {
        service: "dj-ilm",
        number: 3362,
    },
    PortDefinition {
        service: "dtp",
        number: 3663,
    },
    PortDefinition {
        service: "directv-web",
        number: 3334,
    },
    PortDefinition {
        service: "directplaysrvr",
        number: 47624,
    },
    PortDefinition {
        service: "direcpc-video",
        number: 1825,
    },
    PortDefinition {
        service: "diameter",
        number: 3868,
    },
    PortDefinition {
        service: "d-data-control",
        number: 4302,
    },
    PortDefinition {
        service: "dtpt",
        number: 5721,
    },
    PortDefinition {
        service: "dellwebadmin-2",
        number: 1279,
    },
    PortDefinition {
        service: "netmon",
        number: 2606,
    },
    PortDefinition {
        service: "d-cinema-rrp",
        number: 1173,
    },
    PortDefinition {
        service: "dcap",
        number: 22125,
    },
    PortDefinition {
        service: "db-lsp",
        number: 17500,
    },
    PortDefinition {
        service: "dbisamserver1",
        number: 12005,
    },
    PortDefinition {
        service: "dayliteserver",
        number: 6113,
    },
    PortDefinition {
        service: "dcsoftware",
        number: 3793,
    },
    PortDefinition {
        service: "dlsrap",
        number: 1973,
    },
    PortDefinition {
        service: "scservp",
        number: 3637,
    },
    PortDefinition {
        service: "cumulus-admin",
        number: 8954,
    },
    PortDefinition {
        service: "cst-port",
        number: 3742,
    },
    PortDefinition {
        service: "xmms2",
        number: 9667,
    },
    PortDefinition {
        service: "crestron-ctp",
        number: 41795,
    },
    PortDefinition {
        service: "crestron-cip",
        number: 41794,
    },
    PortDefinition {
        service: "corelccam",
        number: 4300,
    },
    PortDefinition {
        service: "copy",
        number: 8445,
    },
    PortDefinition {
        service: "netperf",
        number: 12865,
    },
    PortDefinition {
        service: "contentserver",
        number: 3365,
    },
    PortDefinition {
        service: "contclientms",
        number: 4665,
    },
    PortDefinition {
        service: "csvr-proxy",
        number: 3190,
    },
    PortDefinition {
        service: "config-port",
        number: 3577,
    },
    PortDefinition {
        service: "acp-conduit",
        number: 3823,
    },
    PortDefinition {
        service: "comotionmaster",
        number: 2261,
    },
    PortDefinition {
        service: "comotionback",
        number: 2262,
    },
    PortDefinition {
        service: "atmtcp",
        number: 2812,
    },
    PortDefinition {
        service: "commlinx-avl",
        number: 1190,
    },
    PortDefinition {
        service: "CodeMeter",
        number: 22350,
    },
    PortDefinition {
        service: "cluster-disc",
        number: 3374,
    },
    PortDefinition {
        service: "cl-db-attach",
        number: 4135,
    },
    PortDefinition {
        service: "citriximaclient",
        number: 2598,
    },
    PortDefinition {
        service: "clp",
        number: 2567,
    },
    PortDefinition {
        service: "cisco-ipsla",
        number: 1167,
    },
    PortDefinition {
        service: "cisco-avp",
        number: 8470,
    },
    PortDefinition {
        service: "cirrossp",
        number: 10443,
    },
    PortDefinition {
        service: "cp-cluster",
        number: 8116,
    },
    PortDefinition {
        service: "cernsysmgmtagt",
        number: 3830,
    },
    PortDefinition {
        service: "cddbp-alt",
        number: 8880,
    },
    PortDefinition {
        service: "ccs-software",
        number: 2734,
    },
    PortDefinition {
        service: "ccmcomm",
        number: 3505,
    },
    PortDefinition {
        service: "cbserver",
        number: 3388,
    },
    PortDefinition {
        service: "canocentral0",
        number: 1871,
    },
    PortDefinition {
        service: "geognosisman",
        number: 4325,
    },
    PortDefinition {
        service: "casanswmgmt",
        number: 3669,
    },
    PortDefinition {
        service: "ca-audit-da",
        number: 8025,
    },
    PortDefinition {
        service: "dxadmind",
        number: 1958,
    },
    PortDefinition {
        service: "bts-x73",
        number: 3681,
    },
    PortDefinition {
        service: "broker_service",
        number: 3014,
    },
    PortDefinition {
        service: "bctp",
        number: 8999,
    },
    PortDefinition {
        service: "brcd-vr-req",
        number: 4415,
    },
    PortDefinition {
        service: "wip-port",
        number: 3414,
    },
    PortDefinition {
        service: "brlp-0",
        number: 4101,
    },
    PortDefinition {
        service: "boks_clntd",
        number: 6503,
    },
    PortDefinition {
        service: "board-roar",
        number: 9700,
    },
    PortDefinition {
        service: "bmc-ea",
        number: 3683,
    },
    PortDefinition {
        service: "blaze",
        number: 1150,
    },
    PortDefinition {
        service: "bitcoin",
        number: 18333,
    },
    PortDefinition {
        service: "bip",
        number: 4376,
    },
    PortDefinition {
        service: "bv-smcsrv",
        number: 3991,
    },
    PortDefinition {
        service: "bv-queryengine",
        number: 3989,
    },
    PortDefinition {
        service: "bv-ds",
        number: 3992,
    },
    PortDefinition {
        service: "binderysupport",
        number: 2302,
    },
    PortDefinition {
        service: "bcinameservice",
        number: 3415,
    },
    PortDefinition {
        service: "backupedge",
        number: 3946,
    },
    PortDefinition {
        service: "b2n",
        number: 1179,
    },
    PortDefinition {
        service: "b2-runtime",
        number: 2203,
    },
    PortDefinition {
        service: "azeti",
        number: 4192,
    },
    PortDefinition {
        service: "axysbridge",
        number: 4418,
    },
    PortDefinition {
        service: "aocp",
        number: 2712,
    },
    PortDefinition {
        service: "avanti_cdp",
        number: 4065,
    },
    PortDefinition {
        service: "agcat",
        number: 3915,
    },
    PortDefinition {
        service: "autodesk-nlm",
        number: 2080,
    },
    PortDefinition {
        service: "autocuesmi",
        number: 3103,
    },
    PortDefinition {
        service: "aesop",
        number: 8202,
    },
    PortDefinition {
        service: "apx500api-2",
        number: 2265,
    },
    PortDefinition {
        service: "attachmate-uts",
        number: 2304,
    },
    PortDefinition {
        service: "aero",
        number: 8060,
    },
    PortDefinition {
        service: "assuria-slm",
        number: 4119,
    },
    PortDefinition {
        service: "ds-srvr",
        number: 4401,
    },
    PortDefinition {
        service: "asci-val",
        number: 1560,
    },
    PortDefinition {
        service: "omnilink-port",
        number: 3904,
    },
    PortDefinition {
        service: "armagetronad",
        number: 4534,
    },
    PortDefinition {
        service: "ardusmul",
        number: 1835,
    },
    PortDefinition {
        service: "ardus-cntl",
        number: 1116,
    },
    PortDefinition {
        service: "arca-api",
        number: 8023,
    },
    PortDefinition {
        service: "noteshare",
        number: 8474,
    },
    PortDefinition {
        service: "appss-lm",
        number: 3879,
    },
    PortDefinition {
        service: "applusservice",
        number: 4087,
    },
    PortDefinition {
        service: "apple-vpns-rp",
        number: 4112,
    },
    PortDefinition {
        service: "adap",
        number: 6350,
    },
    PortDefinition {
        service: "apc-9950",
        number: 9950,
    },
    PortDefinition {
        service: "apc-3506",
        number: 3506,
    },
    PortDefinition {
        service: "apdap",
        number: 3948,
    },
    PortDefinition {
        service: "ffserver",
        number: 3825,
    },
    PortDefinition {
        service: "ansys-lm",
        number: 1800,
    },
    PortDefinition {
        service: "ansysli",
        number: 2325,
    },
    PortDefinition {
        service: "c1222-acse",
        number: 1153,
    },
    PortDefinition {
        service: "redis",
        number: 6379,
    },
    PortDefinition {
        service: "amx-rms",
        number: 3839,
    },
    PortDefinition {
        service: "amqp",
        number: 5672,
    },
    PortDefinition {
        service: "altovacentral",
        number: 4689,
    },
    PortDefinition {
        service: "ap",
        number: 47806,
    },
    PortDefinition {
        service: "acms",
        number: 3980,
    },
    PortDefinition {
        service: "airshot",
        number: 3975,
    },
    PortDefinition {
        service: "aipn-reg",
        number: 4113,
    },
    PortDefinition {
        service: "aimpp-port-req",
        number: 2847,
    },
    PortDefinition {
        service: "ah-esp-encap",
        number: 2070,
    },
    PortDefinition {
        service: "agps-port",
        number: 3425,
    },
    PortDefinition {
        service: "afesc-mc",
        number: 6628,
    },
    PortDefinition {
        service: "agentsease-db",
        number: 3997,
    },
    PortDefinition {
        service: "arcpd",
        number: 3513,
    },
    PortDefinition {
        service: "abatjss",
        number: 3656,
    },
    PortDefinition {
        service: "ace-proxy",
        number: 2335,
    },
    PortDefinition {
        service: "accelenet",
        number: 1182,
    },
    PortDefinition {
        service: "abr-api",
        number: 1954,
    },
    PortDefinition {
        service: "abcsoftware",
        number: 3996,
    },
    PortDefinition {
        service: "a17-an-an",
        number: 4599,
    },
    PortDefinition {
        service: "minecraft",
        number: 25565,
    },
    PortDefinition {
        service: "3com-net-mgmt",
        number: 2391,
    },
    PortDefinition {
        service: "twrpc",
        number: 3479,
    },
    PortDefinition {
        service: "zenginkyo-2",
        number: 5021,
    },
    PortDefinition {
        service: "zenginkyo-1",
        number: 5020,
    },
    PortDefinition {
        service: "xingmpeg",
        number: 1558,
    },
    PortDefinition {
        service: "xiip",
        number: 1924,
    },
    PortDefinition {
        service: "worldscores",
        number: 4545,
    },
    PortDefinition {
        service: "wkstn-mon",
        number: 2991,
    },
    PortDefinition {
        service: "winpharaoh",
        number: 6065,
    },
    PortDefinition {
        service: "winjaserver",
        number: 1290,
    },
    PortDefinition {
        service: "web2host",
        number: 1559,
    },
    PortDefinition {
        service: "vrts-ipcserver",
        number: 1317,
    },
    PortDefinition {
        service: "virtualuser",
        number: 5423,
    },
    PortDefinition {
        service: "vdmplay",
        number: 1707,
    },
    PortDefinition {
        service: "unot",
        number: 5055,
    },
    PortDefinition {
        service: "unknown",
        number: 9975,
    },
    PortDefinition {
        service: "unknown",
        number: 9971,
    },
    PortDefinition {
        service: "unknown",
        number: 9919,
    },
    PortDefinition {
        service: "unknown",
        number: 9915,
    },
    PortDefinition {
        service: "unknown",
        number: 9912,
    },
    PortDefinition {
        service: "unknown",
        number: 9910,
    },
    PortDefinition {
        service: "unknown",
        number: 9908,
    },
    PortDefinition {
        service: "unknown",
        number: 9901,
    },
    PortDefinition {
        service: "unknown",
        number: 9844,
    },
    PortDefinition {
        service: "unknown",
        number: 9830,
    },
    PortDefinition {
        service: "unknown",
        number: 9826,
    },
    PortDefinition {
        service: "unknown",
        number: 9825,
    },
    PortDefinition {
        service: "unknown",
        number: 9823,
    },
    PortDefinition {
        service: "unknown",
        number: 9814,
    },
    PortDefinition {
        service: "unknown",
        number: 9812,
    },
    PortDefinition {
        service: "unknown",
        number: 9777,
    },
    PortDefinition {
        service: "unknown",
        number: 9745,
    },
    PortDefinition {
        service: "unknown",
        number: 9683,
    },
    PortDefinition {
        service: "unknown",
        number: 9680,
    },
    PortDefinition {
        service: "unknown",
        number: 9679,
    },
    PortDefinition {
        service: "unknown",
        number: 9674,
    },
    PortDefinition {
        service: "unknown",
        number: 9665,
    },
    PortDefinition {
        service: "unknown",
        number: 9661,
    },
    PortDefinition {
        service: "unknown",
        number: 9654,
    },
    PortDefinition {
        service: "unknown",
        number: 9648,
    },
    PortDefinition {
        service: "unknown",
        number: 9620,
    },
    PortDefinition {
        service: "unknown",
        number: 9619,
    },
    PortDefinition {
        service: "unknown",
        number: 9613,
    },
    PortDefinition {
        service: "unknown",
        number: 9583,
    },
    PortDefinition {
        service: "unknown",
        number: 9527,
    },
    PortDefinition {
        service: "unknown",
        number: 9513,
    },
    PortDefinition {
        service: "unknown",
        number: 9493,
    },
    PortDefinition {
        service: "unknown",
        number: 9478,
    },
    PortDefinition {
        service: "unknown",
        number: 9464,
    },
    PortDefinition {
        service: "unknown",
        number: 9454,
    },
    PortDefinition {
        service: "unknown",
        number: 9364,
    },
    PortDefinition {
        service: "unknown",
        number: 9351,
    },
    PortDefinition {
        service: "unknown",
        number: 9183,
    },
    PortDefinition {
        service: "unknown",
        number: 9170,
    },
    PortDefinition {
        service: "unknown",
        number: 9133,
    },
    PortDefinition {
        service: "unknown",
        number: 9130,
    },
    PortDefinition {
        service: "unknown",
        number: 9128,
    },
    PortDefinition {
        service: "unknown",
        number: 9125,
    },
    PortDefinition {
        service: "unknown",
        number: 9065,
    },
    PortDefinition {
        service: "unknown",
        number: 9061,
    },
    PortDefinition {
        service: "unknown",
        number: 9044,
    },
    PortDefinition {
        service: "unknown",
        number: 9037,
    },
    PortDefinition {
        service: "unknown",
        number: 9013,
    },
    PortDefinition {
        service: "unknown",
        number: 9004,
    },
    PortDefinition {
        service: "unknown",
        number: 8925,
    },
    PortDefinition {
        service: "unknown",
        number: 8898,
    },
    PortDefinition {
        service: "unknown",
        number: 8887,
    },
    PortDefinition {
        service: "unknown",
        number: 8882,
    },
    PortDefinition {
        service: "unknown",
        number: 8879,
    },
    PortDefinition {
        service: "unknown",
        number: 8878,
    },
    PortDefinition {
        service: "unknown",
        number: 8865,
    },
    PortDefinition {
        service: "unknown",
        number: 8843,
    },
    PortDefinition {
        service: "unknown",
        number: 8801,
    },
    PortDefinition {
        service: "unknown",
        number: 8798,
    },
    PortDefinition {
        service: "unknown",
        number: 8790,
    },
    PortDefinition {
        service: "unknown",
        number: 8772,
    },
    PortDefinition {
        service: "unknown",
        number: 8756,
    },
    PortDefinition {
        service: "unknown",
        number: 8752,
    },
    PortDefinition {
        service: "unknown",
        number: 8736,
    },
    PortDefinition {
        service: "unknown",
        number: 8680,
    },
    PortDefinition {
        service: "unknown",
        number: 8673,
    },
    PortDefinition {
        service: "unknown",
        number: 8658,
    },
    PortDefinition {
        service: "unknown",
        number: 8655,
    },
    PortDefinition {
        service: "unknown",
        number: 8644,
    },
    PortDefinition {
        service: "unknown",
        number: 8640,
    },
    PortDefinition {
        service: "unknown",
        number: 8621,
    },
    PortDefinition {
        service: "unknown",
        number: 8601,
    },
    PortDefinition {
        service: "unknown",
        number: 8562,
    },
    PortDefinition {
        service: "unknown",
        number: 8539,
    },
    PortDefinition {
        service: "unknown",
        number: 8531,
    },
    PortDefinition {
        service: "unknown",
        number: 8530,
    },
    PortDefinition {
        service: "unknown",
        number: 8515,
    },
    PortDefinition {
        service: "unknown",
        number: 8484,
    },
    PortDefinition {
        service: "unknown",
        number: 8479,
    },
    PortDefinition {
        service: "unknown",
        number: 8477,
    },
    PortDefinition {
        service: "unknown",
        number: 8455,
    },
    PortDefinition {
        service: "unknown",
        number: 8454,
    },
    PortDefinition {
        service: "unknown",
        number: 8453,
    },
    PortDefinition {
        service: "unknown",
        number: 8452,
    },
    PortDefinition {
        service: "unknown",
        number: 8451,
    },
    PortDefinition {
        service: "unknown",
        number: 8409,
    },
    PortDefinition {
        service: "unknown",
        number: 8339,
    },
    PortDefinition {
        service: "unknown",
        number: 8308,
    },
    PortDefinition {
        service: "unknown",
        number: 8295,
    },
    PortDefinition {
        service: "unknown",
        number: 8273,
    },
    PortDefinition {
        service: "unknown",
        number: 8268,
    },
    PortDefinition {
        service: "unknown",
        number: 8255,
    },
    PortDefinition {
        service: "unknown",
        number: 8248,
    },
    PortDefinition {
        service: "unknown",
        number: 8245,
    },
    PortDefinition {
        service: "unknown",
        number: 8144,
    },
    PortDefinition {
        service: "unknown",
        number: 8133,
    },
    PortDefinition {
        service: "unknown",
        number: 8110,
    },
    PortDefinition {
        service: "unknown",
        number: 8092,
    },
    PortDefinition {
        service: "unknown",
        number: 8064,
    },
    PortDefinition {
        service: "unknown",
        number: 8037,
    },
    PortDefinition {
        service: "unknown",
        number: 8029,
    },
    PortDefinition {
        service: "unknown",
        number: 8018,
    },
    PortDefinition {
        service: "unknown",
        number: 8014,
    },
    PortDefinition {
        service: "unknown",
        number: 7975,
    },
    PortDefinition {
        service: "unknown",
        number: 7895,
    },
    PortDefinition {
        service: "unknown",
        number: 7854,
    },
    PortDefinition {
        service: "unknown",
        number: 7853,
    },
    PortDefinition {
        service: "unknown",
        number: 7852,
    },
    PortDefinition {
        service: "unknown",
        number: 7830,
    },
    PortDefinition {
        service: "unknown",
        number: 7813,
    },
    PortDefinition {
        service: "unknown",
        number: 7788,
    },
    PortDefinition {
        service: "unknown",
        number: 7780,
    },
    PortDefinition {
        service: "unknown",
        number: 7772,
    },
    PortDefinition {
        service: "unknown",
        number: 7771,
    },
    PortDefinition {
        service: "unknown",
        number: 7688,
    },
    PortDefinition {
        service: "unknown",
        number: 7685,
    },
    PortDefinition {
        service: "unknown",
        number: 7654,
    },
    PortDefinition {
        service: "unknown",
        number: 7637,
    },
    PortDefinition {
        service: "unknown",
        number: 7600,
    },
    PortDefinition {
        service: "unknown",
        number: 7555,
    },
    PortDefinition {
        service: "unknown",
        number: 7553,
    },
    PortDefinition {
        service: "unknown",
        number: 7456,
    },
    PortDefinition {
        service: "unknown",
        number: 7451,
    },
    PortDefinition {
        service: "unknown",
        number: 7231,
    },
    PortDefinition {
        service: "unknown",
        number: 7218,
    },
    PortDefinition {
        service: "unknown",
        number: 7184,
    },
    PortDefinition {
        service: "unknown",
        number: 7119,
    },
    PortDefinition {
        service: "unknown",
        number: 7104,
    },
    PortDefinition {
        service: "unknown",
        number: 7102,
    },
    PortDefinition {
        service: "unknown",
        number: 7092,
    },
    PortDefinition {
        service: "unknown",
        number: 7068,
    },
    PortDefinition {
        service: "unknown",
        number: 7067,
    },
    PortDefinition {
        service: "unknown",
        number: 7043,
    },
    PortDefinition {
        service: "unknown",
        number: 7033,
    },
    PortDefinition {
        service: "unknown",
        number: 6973,
    },
    PortDefinition {
        service: "unknown",
        number: 6972,
    },
    PortDefinition {
        service: "unknown",
        number: 6956,
    },
    PortDefinition {
        service: "unknown",
        number: 6942,
    },
    PortDefinition {
        service: "unknown",
        number: 6922,
    },
    PortDefinition {
        service: "unknown",
        number: 6920,
    },
    PortDefinition {
        service: "unknown",
        number: 6897,
    },
    PortDefinition {
        service: "unknown",
        number: 6877,
    },
    PortDefinition {
        service: "unknown",
        number: 6780,
    },
    PortDefinition {
        service: "unknown",
        number: 6734,
    },
    PortDefinition {
        service: "unknown",
        number: 6725,
    },
    PortDefinition {
        service: "unknown",
        number: 6710,
    },
    PortDefinition {
        service: "unknown",
        number: 6709,
    },
    PortDefinition {
        service: "unknown",
        number: 6650,
    },
    PortDefinition {
        service: "unknown",
        number: 6647,
    },
    PortDefinition {
        service: "unknown",
        number: 6644,
    },
    PortDefinition {
        service: "unknown",
        number: 6606,
    },
    PortDefinition {
        service: "unknown",
        number: 65514,
    },
    PortDefinition {
        service: "unknown",
        number: 65488,
    },
    PortDefinition {
        service: "unknown",
        number: 6535,
    },
    PortDefinition {
        service: "unknown",
        number: 65311,
    },
    PortDefinition {
        service: "unknown",
        number: 65048,
    },
    PortDefinition {
        service: "unknown",
        number: 64890,
    },
    PortDefinition {
        service: "unknown",
        number: 64727,
    },
    PortDefinition {
        service: "unknown",
        number: 64726,
    },
    PortDefinition {
        service: "unknown",
        number: 64551,
    },
    PortDefinition {
        service: "unknown",
        number: 64507,
    },
    PortDefinition {
        service: "unknown",
        number: 64438,
    },
    PortDefinition {
        service: "unknown",
        number: 64320,
    },
    PortDefinition {
        service: "unknown",
        number: 64127,
    },
    PortDefinition {
        service: "unknown",
        number: 6412,
    },
    PortDefinition {
        service: "unknown",
        number: 64080,
    },
    PortDefinition {
        service: "unknown",
        number: 63803,
    },
    PortDefinition {
        service: "unknown",
        number: 63675,
    },
    PortDefinition {
        service: "unknown",
        number: 6349,
    },
    PortDefinition {
        service: "unknown",
        number: 63423,
    },
    PortDefinition {
        service: "unknown",
        number: 6323,
    },
    PortDefinition {
        service: "unknown",
        number: 63156,
    },
    PortDefinition {
        service: "unknown",
        number: 63105,
    },
    PortDefinition {
        service: "unknown",
        number: 6310,
    },
    PortDefinition {
        service: "unknown",
        number: 6309,
    },
    PortDefinition {
        service: "unknown",
        number: 62866,
    },
    PortDefinition {
        service: "unknown",
        number: 6274,
    },
    PortDefinition {
        service: "unknown",
        number: 6273,
    },
    PortDefinition {
        service: "unknown",
        number: 62674,
    },
    PortDefinition {
        service: "unknown",
        number: 6259,
    },
    PortDefinition {
        service: "unknown",
        number: 62570,
    },
    PortDefinition {
        service: "unknown",
        number: 62519,
    },
    PortDefinition {
        service: "unknown",
        number: 6250,
    },
    PortDefinition {
        service: "unknown",
        number: 62312,
    },
    PortDefinition {
        service: "unknown",
        number: 62188,
    },
    PortDefinition {
        service: "unknown",
        number: 62080,
    },
    PortDefinition {
        service: "unknown",
        number: 62042,
    },
    PortDefinition {
        service: "unknown",
        number: 62006,
    },
    PortDefinition {
        service: "unknown",
        number: 61942,
    },
    PortDefinition {
        service: "unknown",
        number: 61851,
    },
    PortDefinition {
        service: "unknown",
        number: 61827,
    },
    PortDefinition {
        service: "unknown",
        number: 61734,
    },
    PortDefinition {
        service: "unknown",
        number: 61722,
    },
    PortDefinition {
        service: "unknown",
        number: 61669,
    },
    PortDefinition {
        service: "unknown",
        number: 61617,
    },
    PortDefinition {
        service: "unknown",
        number: 61616,
    },
    PortDefinition {
        service: "unknown",
        number: 61516,
    },
    PortDefinition {
        service: "unknown",
        number: 61473,
    },
    PortDefinition {
        service: "unknown",
        number: 61402,
    },
    PortDefinition {
        service: "unknown",
        number: 6126,
    },
    PortDefinition {
        service: "unknown",
        number: 6120,
    },
    PortDefinition {
        service: "unknown",
        number: 61170,
    },
    PortDefinition {
        service: "unknown",
        number: 61169,
    },
    PortDefinition {
        service: "unknown",
        number: 61159,
    },
    PortDefinition {
        service: "unknown",
        number: 60989,
    },
    PortDefinition {
        service: "unknown",
        number: 6091,
    },
    PortDefinition {
        service: "unknown",
        number: 6090,
    },
    PortDefinition {
        service: "unknown",
        number: 60794,
    },
    PortDefinition {
        service: "unknown",
        number: 60789,
    },
    PortDefinition {
        service: "unknown",
        number: 60783,
    },
    PortDefinition {
        service: "unknown",
        number: 60782,
    },
    PortDefinition {
        service: "unknown",
        number: 60753,
    },
    PortDefinition {
        service: "unknown",
        number: 60743,
    },
    PortDefinition {
        service: "unknown",
        number: 60728,
    },
    PortDefinition {
        service: "unknown",
        number: 60713,
    },
    PortDefinition {
        service: "unknown",
        number: 6067,
    },
    PortDefinition {
        service: "unknown",
        number: 60628,
    },
    PortDefinition {
        service: "unknown",
        number: 60621,
    },
    PortDefinition {
        service: "unknown",
        number: 60612,
    },
    PortDefinition {
        service: "unknown",
        number: 60579,
    },
    PortDefinition {
        service: "unknown",
        number: 60544,
    },
    PortDefinition {
        service: "unknown",
        number: 60504,
    },
    PortDefinition {
        service: "unknown",
        number: 60492,
    },
    PortDefinition {
        service: "unknown",
        number: 60485,
    },
    PortDefinition {
        service: "unknown",
        number: 60403,
    },
    PortDefinition {
        service: "unknown",
        number: 60401,
    },
    PortDefinition {
        service: "unknown",
        number: 60377,
    },
    PortDefinition {
        service: "unknown",
        number: 60279,
    },
    PortDefinition {
        service: "unknown",
        number: 60243,
    },
    PortDefinition {
        service: "unknown",
        number: 60227,
    },
    PortDefinition {
        service: "unknown",
        number: 60177,
    },
    PortDefinition {
        service: "unknown",
        number: 60111,
    },
    PortDefinition {
        service: "unknown",
        number: 60086,
    },
    PortDefinition {
        service: "unknown",
        number: 60055,
    },
    PortDefinition {
        service: "unknown",
        number: 60003,
    },
    PortDefinition {
        service: "unknown",
        number: 60002,
    },
    PortDefinition {
        service: "unknown",
        number: 60000,
    },
    PortDefinition {
        service: "unknown",
        number: 59987,
    },
    PortDefinition {
        service: "unknown",
        number: 59841,
    },
    PortDefinition {
        service: "unknown",
        number: 59829,
    },
    PortDefinition {
        service: "unknown",
        number: 59810,
    },
    PortDefinition {
        service: "unknown",
        number: 59778,
    },
    PortDefinition {
        service: "unknown",
        number: 5975,
    },
    PortDefinition {
        service: "unknown",
        number: 5974,
    },
    PortDefinition {
        service: "unknown",
        number: 5971,
    },
    PortDefinition {
        service: "unknown",
        number: 59684,
    },
    PortDefinition {
        service: "unknown",
        number: 5966,
    },
    PortDefinition {
        service: "unknown",
        number: 5958,
    },
    PortDefinition {
        service: "unknown",
        number: 59565,
    },
    PortDefinition {
        service: "unknown",
        number: 5954,
    },
    PortDefinition {
        service: "unknown",
        number: 5953,
    },
    PortDefinition {
        service: "unknown",
        number: 59525,
    },
    PortDefinition {
        service: "unknown",
        number: 59510,
    },
    PortDefinition {
        service: "unknown",
        number: 59509,
    },
    PortDefinition {
        service: "unknown",
        number: 59504,
    },
    PortDefinition {
        service: "unknown",
        number: 59499,
    },
    PortDefinition {
        service: "unknown",
        number: 5949,
    },
    PortDefinition {
        service: "unknown",
        number: 5948,
    },
    PortDefinition {
        service: "unknown",
        number: 5945,
    },
    PortDefinition {
        service: "unknown",
        number: 5939,
    },
    PortDefinition {
        service: "unknown",
        number: 5936,
    },
    PortDefinition {
        service: "unknown",
        number: 59340,
    },
    PortDefinition {
        service: "unknown",
        number: 5934,
    },
    PortDefinition {
        service: "unknown",
        number: 5931,
    },
    PortDefinition {
        service: "unknown",
        number: 5927,
    },
    PortDefinition {
        service: "unknown",
        number: 5926,
    },
    PortDefinition {
        service: "unknown",
        number: 5924,
    },
    PortDefinition {
        service: "unknown",
        number: 59239,
    },
    PortDefinition {
        service: "unknown",
        number: 5923,
    },
    PortDefinition {
        service: "unknown",
        number: 5921,
    },
    PortDefinition {
        service: "unknown",
        number: 5920,
    },
    PortDefinition {
        service: "unknown",
        number: 59191,
    },
    PortDefinition {
        service: "unknown",
        number: 5917,
    },
    PortDefinition {
        service: "unknown",
        number: 59160,
    },
    PortDefinition {
        service: "unknown",
        number: 59149,
    },
    PortDefinition {
        service: "unknown",
        number: 59122,
    },
    PortDefinition {
        service: "unknown",
        number: 59107,
    },
    PortDefinition {
        service: "unknown",
        number: 59087,
    },
    PortDefinition {
        service: "unknown",
        number: 5908,
    },
    PortDefinition {
        service: "unknown",
        number: 58991,
    },
    PortDefinition {
        service: "unknown",
        number: 58970,
    },
    PortDefinition {
        service: "unknown",
        number: 58908,
    },
    PortDefinition {
        service: "unknown",
        number: 5888,
    },
    PortDefinition {
        service: "unknown",
        number: 5887,
    },
    PortDefinition {
        service: "unknown",
        number: 5881,
    },
    PortDefinition {
        service: "unknown",
        number: 5878,
    },
    PortDefinition {
        service: "unknown",
        number: 5875,
    },
    PortDefinition {
        service: "unknown",
        number: 5874,
    },
    PortDefinition {
        service: "unknown",
        number: 58721,
    },
    PortDefinition {
        service: "unknown",
        number: 5871,
    },
    PortDefinition {
        service: "unknown",
        number: 58699,
    },
    PortDefinition {
        service: "unknown",
        number: 58634,
    },
    PortDefinition {
        service: "unknown",
        number: 58622,
    },
    PortDefinition {
        service: "unknown",
        number: 58610,
    },
    PortDefinition {
        service: "unknown",
        number: 5860,
    },
    PortDefinition {
        service: "unknown",
        number: 5858,
    },
    PortDefinition {
        service: "unknown",
        number: 58570,
    },
    PortDefinition {
        service: "unknown",
        number: 58562,
    },
    PortDefinition {
        service: "unknown",
        number: 5854,
    },
    PortDefinition {
        service: "unknown",
        number: 5853,
    },
    PortDefinition {
        service: "unknown",
        number: 5852,
    },
    PortDefinition {
        service: "unknown",
        number: 58498,
    },
    PortDefinition {
        service: "unknown",
        number: 5849,
    },
    PortDefinition {
        service: "unknown",
        number: 5848,
    },
    PortDefinition {
        service: "unknown",
        number: 58468,
    },
    PortDefinition {
        service: "unknown",
        number: 58456,
    },
    PortDefinition {
        service: "unknown",
        number: 5845,
    },
    PortDefinition {
        service: "unknown",
        number: 58446,
    },
    PortDefinition {
        service: "unknown",
        number: 58430,
    },
    PortDefinition {
        service: "unknown",
        number: 5840,
    },
    PortDefinition {
        service: "unknown",
        number: 5839,
    },
    PortDefinition {
        service: "unknown",
        number: 5838,
    },
    PortDefinition {
        service: "unknown",
        number: 58374,
    },
    PortDefinition {
        service: "unknown",
        number: 5836,
    },
    PortDefinition {
        service: "unknown",
        number: 5834,
    },
    PortDefinition {
        service: "unknown",
        number: 58310,
    },
    PortDefinition {
        service: "unknown",
        number: 5831,
    },
    PortDefinition {
        service: "unknown",
        number: 58305,
    },
    PortDefinition {
        service: "unknown",
        number: 5827,
    },
    PortDefinition {
        service: "unknown",
        number: 5826,
    },
    PortDefinition {
        service: "unknown",
        number: 58252,
    },
    PortDefinition {
        service: "unknown",
        number: 5824,
    },
    PortDefinition {
        service: "unknown",
        number: 5821,
    },
    PortDefinition {
        service: "unknown",
        number: 5820,
    },
    PortDefinition {
        service: "unknown",
        number: 5817,
    },
    PortDefinition {
        service: "unknown",
        number: 58164,
    },
    PortDefinition {
        service: "unknown",
        number: 58109,
    },
    PortDefinition {
        service: "unknown",
        number: 58107,
    },
    PortDefinition {
        service: "unknown",
        number: 5808,
    },
    PortDefinition {
        service: "unknown",
        number: 58072,
    },
    PortDefinition {
        service: "unknown",
        number: 5806,
    },
    PortDefinition {
        service: "unknown",
        number: 5804,
    },
    PortDefinition {
        service: "unknown",
        number: 57999,
    },
    PortDefinition {
        service: "unknown",
        number: 57988,
    },
    PortDefinition {
        service: "unknown",
        number: 57928,
    },
    PortDefinition {
        service: "unknown",
        number: 57923,
    },
    PortDefinition {
        service: "unknown",
        number: 57896,
    },
    PortDefinition {
        service: "unknown",
        number: 57891,
    },
    PortDefinition {
        service: "unknown",
        number: 57733,
    },
    PortDefinition {
        service: "unknown",
        number: 57730,
    },
    PortDefinition {
        service: "unknown",
        number: 57702,
    },
    PortDefinition {
        service: "unknown",
        number: 57681,
    },
    PortDefinition {
        service: "unknown",
        number: 57678,
    },
    PortDefinition {
        service: "unknown",
        number: 57576,
    },
    PortDefinition {
        service: "unknown",
        number: 57479,
    },
    PortDefinition {
        service: "unknown",
        number: 57398,
    },
    PortDefinition {
        service: "unknown",
        number: 57387,
    },
    PortDefinition {
        service: "unknown",
        number: 5737,
    },
    PortDefinition {
        service: "unknown",
        number: 57352,
    },
    PortDefinition {
        service: "unknown",
        number: 57350,
    },
    PortDefinition {
        service: "unknown",
        number: 57347,
    },
    PortDefinition {
        service: "unknown",
        number: 5734,
    },
    PortDefinition {
        service: "unknown",
        number: 57335,
    },
    PortDefinition {
        service: "unknown",
        number: 57325,
    },
    PortDefinition {
        service: "unknown",
        number: 5732,
    },
    PortDefinition {
        service: "unknown",
        number: 57123,
    },
    PortDefinition {
        service: "unknown",
        number: 5711,
    },
    PortDefinition {
        service: "unknown",
        number: 57103,
    },
    PortDefinition {
        service: "unknown",
        number: 57020,
    },
    PortDefinition {
        service: "unknown",
        number: 56975,
    },
    PortDefinition {
        service: "unknown",
        number: 56973,
    },
    PortDefinition {
        service: "unknown",
        number: 56827,
    },
    PortDefinition {
        service: "unknown",
        number: 56822,
    },
    PortDefinition {
        service: "unknown",
        number: 56810,
    },
    PortDefinition {
        service: "unknown",
        number: 56725,
    },
    PortDefinition {
        service: "unknown",
        number: 56723,
    },
    PortDefinition {
        service: "unknown",
        number: 56681,
    },
    PortDefinition {
        service: "unknown",
        number: 5667,
    },
    PortDefinition {
        service: "unknown",
        number: 56668,
    },
    PortDefinition {
        service: "unknown",
        number: 5665,
    },
    PortDefinition {
        service: "unknown",
        number: 56591,
    },
    PortDefinition {
        service: "unknown",
        number: 56535,
    },
    PortDefinition {
        service: "unknown",
        number: 56507,
    },
    PortDefinition {
        service: "unknown",
        number: 56293,
    },
    PortDefinition {
        service: "unknown",
        number: 56259,
    },
    PortDefinition {
        service: "unknown",
        number: 5622,
    },
    PortDefinition {
        service: "unknown",
        number: 5621,
    },
    PortDefinition {
        service: "unknown",
        number: 5620,
    },
    PortDefinition {
        service: "unknown",
        number: 5612,
    },
    PortDefinition {
        service: "unknown",
        number: 5611,
    },
    PortDefinition {
        service: "unknown",
        number: 56055,
    },
    PortDefinition {
        service: "unknown",
        number: 56016,
    },
    PortDefinition {
        service: "unknown",
        number: 55948,
    },
    PortDefinition {
        service: "unknown",
        number: 55910,
    },
    PortDefinition {
        service: "unknown",
        number: 55907,
    },
    PortDefinition {
        service: "unknown",
        number: 55901,
    },
    PortDefinition {
        service: "unknown",
        number: 55781,
    },
    PortDefinition {
        service: "unknown",
        number: 55773,
    },
    PortDefinition {
        service: "unknown",
        number: 55758,
    },
    PortDefinition {
        service: "unknown",
        number: 55721,
    },
    PortDefinition {
        service: "unknown",
        number: 55684,
    },
    PortDefinition {
        service: "unknown",
        number: 55652,
    },
    PortDefinition {
        service: "unknown",
        number: 55635,
    },
    PortDefinition {
        service: "unknown",
        number: 55579,
    },
    PortDefinition {
        service: "unknown",
        number: 55569,
    },
    PortDefinition {
        service: "unknown",
        number: 55568,
    },
    PortDefinition {
        service: "unknown",
        number: 55556,
    },
    PortDefinition {
        service: "unknown",
        number: 55527,
    },
    PortDefinition {
        service: "unknown",
        number: 5552,
    },
    PortDefinition {
        service: "unknown",
        number: 55479,
    },
    PortDefinition {
        service: "unknown",
        number: 55426,
    },
    PortDefinition {
        service: "unknown",
        number: 55400,
    },
    PortDefinition {
        service: "unknown",
        number: 55382,
    },
    PortDefinition {
        service: "unknown",
        number: 55350,
    },
    PortDefinition {
        service: "unknown",
        number: 55312,
    },
    PortDefinition {
        service: "unknown",
        number: 55227,
    },
    PortDefinition {
        service: "unknown",
        number: 55187,
    },
    PortDefinition {
        service: "unknown",
        number: 55183,
    },
    PortDefinition {
        service: "unknown",
        number: 55000,
    },
    PortDefinition {
        service: "unknown",
        number: 54991,
    },
    PortDefinition {
        service: "unknown",
        number: 54987,
    },
    PortDefinition {
        service: "unknown",
        number: 54907,
    },
    PortDefinition {
        service: "unknown",
        number: 54873,
    },
    PortDefinition {
        service: "unknown",
        number: 54741,
    },
    PortDefinition {
        service: "unknown",
        number: 54722,
    },
    PortDefinition {
        service: "unknown",
        number: 54688,
    },
    PortDefinition {
        service: "unknown",
        number: 54658,
    },
    PortDefinition {
        service: "unknown",
        number: 54605,
    },
    PortDefinition {
        service: "unknown",
        number: 5458,
    },
    PortDefinition {
        service: "unknown",
        number: 5457,
    },
    PortDefinition {
        service: "unknown",
        number: 54551,
    },
    PortDefinition {
        service: "unknown",
        number: 54514,
    },
    PortDefinition {
        service: "unknown",
        number: 5444,
    },
    PortDefinition {
        service: "unknown",
        number: 5442,
    },
    PortDefinition {
        service: "unknown",
        number: 5441,
    },
    PortDefinition {
        service: "unknown",
        number: 54323,
    },
    PortDefinition {
        service: "unknown",
        number: 54321,
    },
    PortDefinition {
        service: "unknown",
        number: 54276,
    },
    PortDefinition {
        service: "unknown",
        number: 54263,
    },
    PortDefinition {
        service: "unknown",
        number: 54235,
    },
    PortDefinition {
        service: "unknown",
        number: 54127,
    },
    PortDefinition {
        service: "unknown",
        number: 54101,
    },
    PortDefinition {
        service: "unknown",
        number: 54075,
    },
    PortDefinition {
        service: "unknown",
        number: 53958,
    },
    PortDefinition {
        service: "unknown",
        number: 53910,
    },
    PortDefinition {
        service: "unknown",
        number: 53852,
    },
    PortDefinition {
        service: "unknown",
        number: 53827,
    },
    PortDefinition {
        service: "unknown",
        number: 53782,
    },
    PortDefinition {
        service: "unknown",
        number: 5377,
    },
    PortDefinition {
        service: "unknown",
        number: 53742,
    },
    PortDefinition {
        service: "unknown",
        number: 5370,
    },
    PortDefinition {
        service: "unknown",
        number: 53690,
    },
    PortDefinition {
        service: "unknown",
        number: 53656,
    },
    PortDefinition {
        service: "unknown",
        number: 53639,
    },
    PortDefinition {
        service: "unknown",
        number: 53633,
    },
    PortDefinition {
        service: "unknown",
        number: 53491,
    },
    PortDefinition {
        service: "unknown",
        number: 5347,
    },
    PortDefinition {
        service: "unknown",
        number: 53469,
    },
    PortDefinition {
        service: "unknown",
        number: 53460,
    },
    PortDefinition {
        service: "unknown",
        number: 53370,
    },
    PortDefinition {
        service: "unknown",
        number: 53361,
    },
    PortDefinition {
        service: "unknown",
        number: 53319,
    },
    PortDefinition {
        service: "unknown",
        number: 53240,
    },
    PortDefinition {
        service: "unknown",
        number: 53212,
    },
    PortDefinition {
        service: "unknown",
        number: 53189,
    },
    PortDefinition {
        service: "unknown",
        number: 53178,
    },
    PortDefinition {
        service: "unknown",
        number: 53085,
    },
    PortDefinition {
        service: "unknown",
        number: 52948,
    },
    PortDefinition {
        service: "unknown",
        number: 5291,
    },
    PortDefinition {
        service: "unknown",
        number: 52893,
    },
    PortDefinition {
        service: "unknown",
        number: 52675,
    },
    PortDefinition {
        service: "unknown",
        number: 52665,
    },
    PortDefinition {
        service: "unknown",
        number: 5261,
    },
    PortDefinition {
        service: "unknown",
        number: 5259,
    },
    PortDefinition {
        service: "unknown",
        number: 52573,
    },
    PortDefinition {
        service: "unknown",
        number: 52506,
    },
    PortDefinition {
        service: "unknown",
        number: 52477,
    },
    PortDefinition {
        service: "unknown",
        number: 52391,
    },
    PortDefinition {
        service: "unknown",
        number: 52262,
    },
    PortDefinition {
        service: "unknown",
        number: 52237,
    },
    PortDefinition {
        service: "unknown",
        number: 52230,
    },
    PortDefinition {
        service: "unknown",
        number: 52226,
    },
    PortDefinition {
        service: "unknown",
        number: 52225,
    },
    PortDefinition {
        service: "unknown",
        number: 5219,
    },
    PortDefinition {
        service: "unknown",
        number: 52173,
    },
    PortDefinition {
        service: "unknown",
        number: 52071,
    },
    PortDefinition {
        service: "unknown",
        number: 52046,
    },
    PortDefinition {
        service: "unknown",
        number: 52025,
    },
    PortDefinition {
        service: "unknown",
        number: 52003,
    },
    PortDefinition {
        service: "unknown",
        number: 52002,
    },
    PortDefinition {
        service: "unknown",
        number: 52001,
    },
    PortDefinition {
        service: "unknown",
        number: 52000,
    },
    PortDefinition {
        service: "unknown",
        number: 51965,
    },
    PortDefinition {
        service: "unknown",
        number: 51961,
    },
    PortDefinition {
        service: "unknown",
        number: 51909,
    },
    PortDefinition {
        service: "unknown",
        number: 51906,
    },
    PortDefinition {
        service: "unknown",
        number: 51809,
    },
    PortDefinition {
        service: "unknown",
        number: 51800,
    },
    PortDefinition {
        service: "unknown",
        number: 51772,
    },
    PortDefinition {
        service: "unknown",
        number: 51771,
    },
    PortDefinition {
        service: "unknown",
        number: 51658,
    },
    PortDefinition {
        service: "unknown",
        number: 51582,
    },
    PortDefinition {
        service: "unknown",
        number: 51515,
    },
    PortDefinition {
        service: "unknown",
        number: 51488,
    },
    PortDefinition {
        service: "unknown",
        number: 51485,
    },
    PortDefinition {
        service: "unknown",
        number: 51484,
    },
    PortDefinition {
        service: "unknown",
        number: 5147,
    },
    PortDefinition {
        service: "unknown",
        number: 51460,
    },
    PortDefinition {
        service: "unknown",
        number: 51423,
    },
    PortDefinition {
        service: "unknown",
        number: 51366,
    },
    PortDefinition {
        service: "unknown",
        number: 51351,
    },
    PortDefinition {
        service: "unknown",
        number: 51343,
    },
    PortDefinition {
        service: "unknown",
        number: 51300,
    },
    PortDefinition {
        service: "unknown",
        number: 5125,
    },
    PortDefinition {
        service: "unknown",
        number: 51240,
    },
    PortDefinition {
        service: "unknown",
        number: 51235,
    },
    PortDefinition {
        service: "unknown",
        number: 51234,
    },
    PortDefinition {
        service: "unknown",
        number: 51233,
    },
    PortDefinition {
        service: "unknown",
        number: 5122,
    },
    PortDefinition {
        service: "unknown",
        number: 5121,
    },
    PortDefinition {
        service: "unknown",
        number: 51139,
    },
    PortDefinition {
        service: "unknown",
        number: 51118,
    },
    PortDefinition {
        service: "unknown",
        number: 51067,
    },
    PortDefinition {
        service: "unknown",
        number: 51037,
    },
    PortDefinition {
        service: "unknown",
        number: 51020,
    },
    PortDefinition {
        service: "unknown",
        number: 51011,
    },
    PortDefinition {
        service: "unknown",
        number: 50997,
    },
    PortDefinition {
        service: "unknown",
        number: 5098,
    },
    PortDefinition {
        service: "unknown",
        number: 5096,
    },
    PortDefinition {
        service: "unknown",
        number: 5095,
    },
    PortDefinition {
        service: "unknown",
        number: 50945,
    },
    PortDefinition {
        service: "unknown",
        number: 50903,
    },
    PortDefinition {
        service: "unknown",
        number: 5090,
    },
    PortDefinition {
        service: "unknown",
        number: 50887,
    },
    PortDefinition {
        service: "unknown",
        number: 5088,
    },
    PortDefinition {
        service: "unknown",
        number: 50854,
    },
    PortDefinition {
        service: "unknown",
        number: 50849,
    },
    PortDefinition {
        service: "unknown",
        number: 50836,
    },
    PortDefinition {
        service: "unknown",
        number: 50835,
    },
    PortDefinition {
        service: "unknown",
        number: 50834,
    },
    PortDefinition {
        service: "unknown",
        number: 50833,
    },
    PortDefinition {
        service: "unknown",
        number: 50831,
    },
    PortDefinition {
        service: "unknown",
        number: 50815,
    },
    PortDefinition {
        service: "unknown",
        number: 50809,
    },
    PortDefinition {
        service: "unknown",
        number: 50787,
    },
    PortDefinition {
        service: "unknown",
        number: 50733,
    },
    PortDefinition {
        service: "unknown",
        number: 50692,
    },
    PortDefinition {
        service: "unknown",
        number: 50585,
    },
    PortDefinition {
        service: "unknown",
        number: 50577,
    },
    PortDefinition {
        service: "unknown",
        number: 50576,
    },
    PortDefinition {
        service: "unknown",
        number: 50545,
    },
    PortDefinition {
        service: "unknown",
        number: 50529,
    },
    PortDefinition {
        service: "unknown",
        number: 50513,
    },
    PortDefinition {
        service: "unknown",
        number: 50356,
    },
    PortDefinition {
        service: "unknown",
        number: 50277,
    },
    PortDefinition {
        service: "unknown",
        number: 50258,
    },
    PortDefinition {
        service: "unknown",
        number: 50246,
    },
    PortDefinition {
        service: "unknown",
        number: 50224,
    },
    PortDefinition {
        service: "unknown",
        number: 50205,
    },
    PortDefinition {
        service: "unknown",
        number: 50202,
    },
    PortDefinition {
        service: "unknown",
        number: 50198,
    },
    PortDefinition {
        service: "unknown",
        number: 50189,
    },
    PortDefinition {
        service: "unknown",
        number: 5017,
    },
    PortDefinition {
        service: "unknown",
        number: 5016,
    },
    PortDefinition {
        service: "unknown",
        number: 50101,
    },
    PortDefinition {
        service: "unknown",
        number: 50040,
    },
    PortDefinition {
        service: "unknown",
        number: 50019,
    },
    PortDefinition {
        service: "unknown",
        number: 50016,
    },
    PortDefinition {
        service: "unknown",
        number: 49927,
    },
    PortDefinition {
        service: "unknown",
        number: 49803,
    },
    PortDefinition {
        service: "unknown",
        number: 49765,
    },
    PortDefinition {
        service: "unknown",
        number: 49762,
    },
    PortDefinition {
        service: "unknown",
        number: 49751,
    },
    PortDefinition {
        service: "unknown",
        number: 49678,
    },
    PortDefinition {
        service: "unknown",
        number: 49603,
    },
    PortDefinition {
        service: "unknown",
        number: 49597,
    },
    PortDefinition {
        service: "unknown",
        number: 49522,
    },
    PortDefinition {
        service: "unknown",
        number: 49521,
    },
    PortDefinition {
        service: "unknown",
        number: 49520,
    },
    PortDefinition {
        service: "unknown",
        number: 49519,
    },
    PortDefinition {
        service: "unknown",
        number: 49500,
    },
    PortDefinition {
        service: "unknown",
        number: 49498,
    },
    PortDefinition {
        service: "unknown",
        number: 49452,
    },
    PortDefinition {
        service: "unknown",
        number: 49398,
    },
    PortDefinition {
        service: "unknown",
        number: 49372,
    },
    PortDefinition {
        service: "unknown",
        number: 49352,
    },
    PortDefinition {
        service: "unknown",
        number: 4931,
    },
    PortDefinition {
        service: "unknown",
        number: 49302,
    },
    PortDefinition {
        service: "unknown",
        number: 49275,
    },
    PortDefinition {
        service: "unknown",
        number: 49241,
    },
    PortDefinition {
        service: "unknown",
        number: 49235,
    },
    PortDefinition {
        service: "unknown",
        number: 49232,
    },
    PortDefinition {
        service: "unknown",
        number: 49228,
    },
    PortDefinition {
        service: "unknown",
        number: 49216,
    },
    PortDefinition {
        service: "unknown",
        number: 49213,
    },
    PortDefinition {
        service: "unknown",
        number: 49211,
    },
    PortDefinition {
        service: "unknown",
        number: 49204,
    },
    PortDefinition {
        service: "unknown",
        number: 49203,
    },
    PortDefinition {
        service: "unknown",
        number: 49202,
    },
    PortDefinition {
        service: "unknown",
        number: 49201,
    },
    PortDefinition {
        service: "unknown",
        number: 49197,
    },
    PortDefinition {
        service: "unknown",
        number: 49196,
    },
    PortDefinition {
        service: "unknown",
        number: 49191,
    },
    PortDefinition {
        service: "unknown",
        number: 49190,
    },
    PortDefinition {
        service: "unknown",
        number: 49189,
    },
    PortDefinition {
        service: "unknown",
        number: 49179,
    },
    PortDefinition {
        service: "unknown",
        number: 49173,
    },
    PortDefinition {
        service: "unknown",
        number: 49172,
    },
    PortDefinition {
        service: "unknown",
        number: 49170,
    },
    PortDefinition {
        service: "unknown",
        number: 49169,
    },
    PortDefinition {
        service: "unknown",
        number: 49166,
    },
    PortDefinition {
        service: "unknown",
        number: 49132,
    },
    PortDefinition {
        service: "unknown",
        number: 49048,
    },
    PortDefinition {
        service: "unknown",
        number: 4903,
    },
    PortDefinition {
        service: "unknown",
        number: 49002,
    },
    PortDefinition {
        service: "unknown",
        number: 48973,
    },
    PortDefinition {
        service: "unknown",
        number: 48967,
    },
    PortDefinition {
        service: "unknown",
        number: 48966,
    },
    PortDefinition {
        service: "unknown",
        number: 48925,
    },
    PortDefinition {
        service: "unknown",
        number: 48813,
    },
    PortDefinition {
        service: "unknown",
        number: 48783,
    },
    PortDefinition {
        service: "unknown",
        number: 48682,
    },
    PortDefinition {
        service: "unknown",
        number: 48648,
    },
    PortDefinition {
        service: "unknown",
        number: 48631,
    },
    PortDefinition {
        service: "unknown",
        number: 4860,
    },
    PortDefinition {
        service: "unknown",
        number: 4859,
    },
    PortDefinition {
        service: "unknown",
        number: 48434,
    },
    PortDefinition {
        service: "unknown",
        number: 48356,
    },
    PortDefinition {
        service: "unknown",
        number: 4819,
    },
    PortDefinition {
        service: "unknown",
        number: 48167,
    },
    PortDefinition {
        service: "unknown",
        number: 48153,
    },
    PortDefinition {
        service: "unknown",
        number: 48127,
    },
    PortDefinition {
        service: "unknown",
        number: 48083,
    },
    PortDefinition {
        service: "unknown",
        number: 48067,
    },
    PortDefinition {
        service: "unknown",
        number: 48009,
    },
    PortDefinition {
        service: "unknown",
        number: 47969,
    },
    PortDefinition {
        service: "unknown",
        number: 47966,
    },
    PortDefinition {
        service: "unknown",
        number: 4793,
    },
    PortDefinition {
        service: "unknown",
        number: 47860,
    },
    PortDefinition {
        service: "unknown",
        number: 47858,
    },
    PortDefinition {
        service: "unknown",
        number: 47850,
    },
    PortDefinition {
        service: "unknown",
        number: 4778,
    },
    PortDefinition {
        service: "unknown",
        number: 47777,
    },
    PortDefinition {
        service: "unknown",
        number: 4771,
    },
    PortDefinition {
        service: "unknown",
        number: 47700,
    },
    PortDefinition {
        service: "unknown",
        number: 4770,
    },
    PortDefinition {
        service: "unknown",
        number: 4767,
    },
    PortDefinition {
        service: "unknown",
        number: 47634,
    },
    PortDefinition {
        service: "unknown",
        number: 4760,
    },
    PortDefinition {
        service: "unknown",
        number: 47595,
    },
    PortDefinition {
        service: "unknown",
        number: 47581,
    },
    PortDefinition {
        service: "unknown",
        number: 47567,
    },
    PortDefinition {
        service: "unknown",
        number: 47448,
    },
    PortDefinition {
        service: "unknown",
        number: 47372,
    },
    PortDefinition {
        service: "unknown",
        number: 47348,
    },
    PortDefinition {
        service: "unknown",
        number: 47267,
    },
    PortDefinition {
        service: "unknown",
        number: 47197,
    },
    PortDefinition {
        service: "unknown",
        number: 4712,
    },
    PortDefinition {
        service: "unknown",
        number: 47119,
    },
    PortDefinition {
        service: "unknown",
        number: 47029,
    },
    PortDefinition {
        service: "unknown",
        number: 47012,
    },
    PortDefinition {
        service: "unknown",
        number: 46992,
    },
    PortDefinition {
        service: "unknown",
        number: 46813,
    },
    PortDefinition {
        service: "unknown",
        number: 46593,
    },
    PortDefinition {
        service: "unknown",
        number: 4649,
    },
    PortDefinition {
        service: "unknown",
        number: 4644,
    },
    PortDefinition {
        service: "unknown",
        number: 46436,
    },
    PortDefinition {
        service: "unknown",
        number: 46418,
    },
    PortDefinition {
        service: "unknown",
        number: 46372,
    },
    PortDefinition {
        service: "unknown",
        number: 46310,
    },
    PortDefinition {
        service: "unknown",
        number: 46182,
    },
    PortDefinition {
        service: "unknown",
        number: 46171,
    },
    PortDefinition {
        service: "unknown",
        number: 46115,
    },
    PortDefinition {
        service: "unknown",
        number: 4609,
    },
    PortDefinition {
        service: "unknown",
        number: 46069,
    },
    PortDefinition {
        service: "unknown",
        number: 46034,
    },
    PortDefinition {
        service: "unknown",
        number: 45960,
    },
    PortDefinition {
        service: "unknown",
        number: 45864,
    },
    PortDefinition {
        service: "unknown",
        number: 45777,
    },
    PortDefinition {
        service: "unknown",
        number: 45697,
    },
    PortDefinition {
        service: "unknown",
        number: 45624,
    },
    PortDefinition {
        service: "unknown",
        number: 45602,
    },
    PortDefinition {
        service: "unknown",
        number: 45463,
    },
    PortDefinition {
        service: "unknown",
        number: 45438,
    },
    PortDefinition {
        service: "unknown",
        number: 45413,
    },
    PortDefinition {
        service: "unknown",
        number: 4530,
    },
    PortDefinition {
        service: "unknown",
        number: 45226,
    },
    PortDefinition {
        service: "unknown",
        number: 45220,
    },
    PortDefinition {
        service: "unknown",
        number: 4517,
    },
    PortDefinition {
        service: "unknown",
        number: 45164,
    },
    PortDefinition {
        service: "unknown",
        number: 4516,
    },
    PortDefinition {
        service: "unknown",
        number: 45136,
    },
    PortDefinition {
        service: "unknown",
        number: 45050,
    },
    PortDefinition {
        service: "unknown",
        number: 45038,
    },
    PortDefinition {
        service: "unknown",
        number: 44981,
    },
    PortDefinition {
        service: "unknown",
        number: 44965,
    },
    PortDefinition {
        service: "unknown",
        number: 4476,
    },
    PortDefinition {
        service: "unknown",
        number: 44711,
    },
    PortDefinition {
        service: "unknown",
        number: 4471,
    },
    PortDefinition {
        service: "unknown",
        number: 44704,
    },
    PortDefinition {
        service: "unknown",
        number: 4464,
    },
    PortDefinition {
        service: "unknown",
        number: 44628,
    },
    PortDefinition {
        service: "unknown",
        number: 44616,
    },
    PortDefinition {
        service: "unknown",
        number: 44541,
    },
    PortDefinition {
        service: "unknown",
        number: 44505,
    },
    PortDefinition {
        service: "unknown",
        number: 44479,
    },
    PortDefinition {
        service: "unknown",
        number: 44431,
    },
    PortDefinition {
        service: "unknown",
        number: 44410,
    },
    PortDefinition {
        service: "unknown",
        number: 44380,
    },
    PortDefinition {
        service: "unknown",
        number: 44200,
    },
    PortDefinition {
        service: "unknown",
        number: 44119,
    },
    PortDefinition {
        service: "unknown",
        number: 44101,
    },
    PortDefinition {
        service: "unknown",
        number: 44004,
    },
    PortDefinition {
        service: "unknown",
        number: 4388,
    },
    PortDefinition {
        service: "unknown",
        number: 43868,
    },
    PortDefinition {
        service: "unknown",
        number: 4384,
    },
    PortDefinition {
        service: "unknown",
        number: 43823,
    },
    PortDefinition {
        service: "unknown",
        number: 43734,
    },
    PortDefinition {
        service: "unknown",
        number: 43690,
    },
    PortDefinition {
        service: "unknown",
        number: 43654,
    },
    PortDefinition {
        service: "unknown",
        number: 43425,
    },
    PortDefinition {
        service: "unknown",
        number: 43242,
    },
    PortDefinition {
        service: "unknown",
        number: 43231,
    },
    PortDefinition {
        service: "unknown",
        number: 43212,
    },
    PortDefinition {
        service: "unknown",
        number: 43143,
    },
    PortDefinition {
        service: "unknown",
        number: 43139,
    },
    PortDefinition {
        service: "unknown",
        number: 43103,
    },
    PortDefinition {
        service: "unknown",
        number: 43027,
    },
    PortDefinition {
        service: "unknown",
        number: 43018,
    },
    PortDefinition {
        service: "unknown",
        number: 43002,
    },
    PortDefinition {
        service: "unknown",
        number: 42990,
    },
    PortDefinition {
        service: "unknown",
        number: 42906,
    },
    PortDefinition {
        service: "unknown",
        number: 42735,
    },
    PortDefinition {
        service: "unknown",
        number: 42685,
    },
    PortDefinition {
        service: "unknown",
        number: 42679,
    },
    PortDefinition {
        service: "unknown",
        number: 42675,
    },
    PortDefinition {
        service: "unknown",
        number: 42632,
    },
    PortDefinition {
        service: "unknown",
        number: 42590,
    },
    PortDefinition {
        service: "unknown",
        number: 42575,
    },
    PortDefinition {
        service: "unknown",
        number: 42560,
    },
    PortDefinition {
        service: "unknown",
        number: 42559,
    },
    PortDefinition {
        service: "unknown",
        number: 42452,
    },
    PortDefinition {
        service: "unknown",
        number: 42449,
    },
    PortDefinition {
        service: "unknown",
        number: 42322,
    },
    PortDefinition {
        service: "unknown",
        number: 42276,
    },
    PortDefinition {
        service: "unknown",
        number: 42251,
    },
    PortDefinition {
        service: "unknown",
        number: 42158,
    },
    PortDefinition {
        service: "unknown",
        number: 42127,
    },
    PortDefinition {
        service: "unknown",
        number: 42035,
    },
    PortDefinition {
        service: "unknown",
        number: 42001,
    },
    PortDefinition {
        service: "unknown",
        number: 41808,
    },
    PortDefinition {
        service: "unknown",
        number: 41773,
    },
    PortDefinition {
        service: "unknown",
        number: 41632,
    },
    PortDefinition {
        service: "unknown",
        number: 41551,
    },
    PortDefinition {
        service: "unknown",
        number: 41442,
    },
    PortDefinition {
        service: "unknown",
        number: 41398,
    },
    PortDefinition {
        service: "unknown",
        number: 41348,
    },
    PortDefinition {
        service: "unknown",
        number: 41345,
    },
    PortDefinition {
        service: "unknown",
        number: 41342,
    },
    PortDefinition {
        service: "unknown",
        number: 41318,
    },
    PortDefinition {
        service: "unknown",
        number: 41281,
    },
    PortDefinition {
        service: "unknown",
        number: 41250,
    },
    PortDefinition {
        service: "unknown",
        number: 41142,
    },
    PortDefinition {
        service: "unknown",
        number: 41123,
    },
    PortDefinition {
        service: "unknown",
        number: 40951,
    },
    PortDefinition {
        service: "unknown",
        number: 40834,
    },
    PortDefinition {
        service: "unknown",
        number: 40812,
    },
    PortDefinition {
        service: "unknown",
        number: 40754,
    },
    PortDefinition {
        service: "unknown",
        number: 40732,
    },
    PortDefinition {
        service: "unknown",
        number: 40712,
    },
    PortDefinition {
        service: "unknown",
        number: 40628,
    },
    PortDefinition {
        service: "unknown",
        number: 40614,
    },
    PortDefinition {
        service: "unknown",
        number: 40513,
    },
    PortDefinition {
        service: "unknown",
        number: 40489,
    },
    PortDefinition {
        service: "unknown",
        number: 40457,
    },
    PortDefinition {
        service: "unknown",
        number: 40400,
    },
    PortDefinition {
        service: "unknown",
        number: 40393,
    },
    PortDefinition {
        service: "unknown",
        number: 40306,
    },
    PortDefinition {
        service: "unknown",
        number: 40011,
    },
    PortDefinition {
        service: "unknown",
        number: 40005,
    },
    PortDefinition {
        service: "unknown",
        number: 40003,
    },
    PortDefinition {
        service: "unknown",
        number: 40002,
    },
    PortDefinition {
        service: "unknown",
        number: 40001,
    },
    PortDefinition {
        service: "unknown",
        number: 39917,
    },
    PortDefinition {
        service: "unknown",
        number: 39895,
    },
    PortDefinition {
        service: "unknown",
        number: 39883,
    },
    PortDefinition {
        service: "unknown",
        number: 39869,
    },
    PortDefinition {
        service: "unknown",
        number: 39795,
    },
    PortDefinition {
        service: "unknown",
        number: 39774,
    },
    PortDefinition {
        service: "unknown",
        number: 39763,
    },
    PortDefinition {
        service: "unknown",
        number: 39732,
    },
    PortDefinition {
        service: "unknown",
        number: 39630,
    },
    PortDefinition {
        service: "unknown",
        number: 39489,
    },
    PortDefinition {
        service: "unknown",
        number: 39482,
    },
    PortDefinition {
        service: "unknown",
        number: 39433,
    },
    PortDefinition {
        service: "unknown",
        number: 39380,
    },
    PortDefinition {
        service: "unknown",
        number: 39293,
    },
    PortDefinition {
        service: "unknown",
        number: 39265,
    },
    PortDefinition {
        service: "unknown",
        number: 39117,
    },
    PortDefinition {
        service: "unknown",
        number: 39067,
    },
    PortDefinition {
        service: "unknown",
        number: 38936,
    },
    PortDefinition {
        service: "unknown",
        number: 38805,
    },
    PortDefinition {
        service: "unknown",
        number: 38780,
    },
    PortDefinition {
        service: "unknown",
        number: 38764,
    },
    PortDefinition {
        service: "unknown",
        number: 38761,
    },
    PortDefinition {
        service: "unknown",
        number: 38570,
    },
    PortDefinition {
        service: "unknown",
        number: 38561,
    },
    PortDefinition {
        service: "unknown",
        number: 38546,
    },
    PortDefinition {
        service: "unknown",
        number: 38481,
    },
    PortDefinition {
        service: "unknown",
        number: 38446,
    },
    PortDefinition {
        service: "unknown",
        number: 38358,
    },
    PortDefinition {
        service: "unknown",
        number: 38331,
    },
    PortDefinition {
        service: "unknown",
        number: 38313,
    },
    PortDefinition {
        service: "unknown",
        number: 38270,
    },
    PortDefinition {
        service: "unknown",
        number: 38224,
    },
    PortDefinition {
        service: "unknown",
        number: 38205,
    },
    PortDefinition {
        service: "unknown",
        number: 38194,
    },
    PortDefinition {
        service: "unknown",
        number: 38029,
    },
    PortDefinition {
        service: "unknown",
        number: 37855,
    },
    PortDefinition {
        service: "unknown",
        number: 37789,
    },
    PortDefinition {
        service: "unknown",
        number: 37777,
    },
    PortDefinition {
        service: "unknown",
        number: 37674,
    },
    PortDefinition {
        service: "unknown",
        number: 37647,
    },
    PortDefinition {
        service: "unknown",
        number: 37614,
    },
    PortDefinition {
        service: "unknown",
        number: 37607,
    },
    PortDefinition {
        service: "unknown",
        number: 37522,
    },
    PortDefinition {
        service: "unknown",
        number: 37393,
    },
    PortDefinition {
        service: "unknown",
        number: 37218,
    },
    PortDefinition {
        service: "unknown",
        number: 37185,
    },
    PortDefinition {
        service: "unknown",
        number: 37174,
    },
    PortDefinition {
        service: "unknown",
        number: 37151,
    },
    PortDefinition {
        service: "unknown",
        number: 37121,
    },
    PortDefinition {
        service: "unknown",
        number: 36983,
    },
    PortDefinition {
        service: "unknown",
        number: 36962,
    },
    PortDefinition {
        service: "unknown",
        number: 36950,
    },
    PortDefinition {
        service: "unknown",
        number: 36914,
    },
    PortDefinition {
        service: "unknown",
        number: 36824,
    },
    PortDefinition {
        service: "unknown",
        number: 36823,
    },
    PortDefinition {
        service: "unknown",
        number: 36748,
    },
    PortDefinition {
        service: "unknown",
        number: 36710,
    },
    PortDefinition {
        service: "unknown",
        number: 36694,
    },
    PortDefinition {
        service: "unknown",
        number: 36677,
    },
    PortDefinition {
        service: "unknown",
        number: 36659,
    },
    PortDefinition {
        service: "unknown",
        number: 36552,
    },
    PortDefinition {
        service: "unknown",
        number: 36530,
    },
    PortDefinition {
        service: "unknown",
        number: 36508,
    },
    PortDefinition {
        service: "unknown",
        number: 36436,
    },
    PortDefinition {
        service: "unknown",
        number: 36368,
    },
    PortDefinition {
        service: "unknown",
        number: 36275,
    },
    PortDefinition {
        service: "unknown",
        number: 36256,
    },
    PortDefinition {
        service: "unknown",
        number: 36105,
    },
    PortDefinition {
        service: "unknown",
        number: 36104,
    },
    PortDefinition {
        service: "unknown",
        number: 36046,
    },
    PortDefinition {
        service: "unknown",
        number: 35986,
    },
    PortDefinition {
        service: "unknown",
        number: 35929,
    },
    PortDefinition {
        service: "unknown",
        number: 35906,
    },
    PortDefinition {
        service: "unknown",
        number: 35901,
    },
    PortDefinition {
        service: "unknown",
        number: 35900,
    },
    PortDefinition {
        service: "unknown",
        number: 35879,
    },
    PortDefinition {
        service: "unknown",
        number: 35731,
    },
    PortDefinition {
        service: "unknown",
        number: 35593,
    },
    PortDefinition {
        service: "unknown",
        number: 35553,
    },
    PortDefinition {
        service: "unknown",
        number: 35506,
    },
    PortDefinition {
        service: "unknown",
        number: 35401,
    },
    PortDefinition {
        service: "unknown",
        number: 35393,
    },
    PortDefinition {
        service: "unknown",
        number: 35392,
    },
    PortDefinition {
        service: "unknown",
        number: 35349,
    },
    PortDefinition {
        service: "unknown",
        number: 35272,
    },
    PortDefinition {
        service: "unknown",
        number: 35217,
    },
    PortDefinition {
        service: "unknown",
        number: 35131,
    },
    PortDefinition {
        service: "unknown",
        number: 35116,
    },
    PortDefinition {
        service: "unknown",
        number: 35050,
    },
    PortDefinition {
        service: "unknown",
        number: 35033,
    },
    PortDefinition {
        service: "unknown",
        number: 34875,
    },
    PortDefinition {
        service: "unknown",
        number: 34833,
    },
    PortDefinition {
        service: "unknown",
        number: 34783,
    },
    PortDefinition {
        service: "unknown",
        number: 34765,
    },
    PortDefinition {
        service: "unknown",
        number: 34728,
    },
    PortDefinition {
        service: "unknown",
        number: 34683,
    },
    PortDefinition {
        service: "unknown",
        number: 34510,
    },
    PortDefinition {
        service: "unknown",
        number: 34507,
    },
    PortDefinition {
        service: "unknown",
        number: 34401,
    },
    PortDefinition {
        service: "unknown",
        number: 34381,
    },
    PortDefinition {
        service: "unknown",
        number: 34341,
    },
    PortDefinition {
        service: "unknown",
        number: 34317,
    },
    PortDefinition {
        service: "unknown",
        number: 34189,
    },
    PortDefinition {
        service: "unknown",
        number: 34096,
    },
    PortDefinition {
        service: "unknown",
        number: 34036,
    },
    PortDefinition {
        service: "unknown",
        number: 34021,
    },
    PortDefinition {
        service: "unknown",
        number: 33895,
    },
    PortDefinition {
        service: "unknown",
        number: 33889,
    },
    PortDefinition {
        service: "unknown",
        number: 33882,
    },
    PortDefinition {
        service: "unknown",
        number: 33879,
    },
    PortDefinition {
        service: "unknown",
        number: 33841,
    },
    PortDefinition {
        service: "unknown",
        number: 33605,
    },
    PortDefinition {
        service: "unknown",
        number: 33604,
    },
    PortDefinition {
        service: "unknown",
        number: 33550,
    },
    PortDefinition {
        service: "unknown",
        number: 33523,
    },
    PortDefinition {
        service: "unknown",
        number: 33522,
    },
    PortDefinition {
        service: "unknown",
        number: 33444,
    },
    PortDefinition {
        service: "unknown",
        number: 33395,
    },
    PortDefinition {
        service: "unknown",
        number: 33367,
    },
    PortDefinition {
        service: "unknown",
        number: 33337,
    },
    PortDefinition {
        service: "unknown",
        number: 33335,
    },
    PortDefinition {
        service: "unknown",
        number: 33327,
    },
    PortDefinition {
        service: "unknown",
        number: 33277,
    },
    PortDefinition {
        service: "unknown",
        number: 33203,
    },
    PortDefinition {
        service: "unknown",
        number: 33200,
    },
    PortDefinition {
        service: "unknown",
        number: 33192,
    },
    PortDefinition {
        service: "unknown",
        number: 33175,
    },
    PortDefinition {
        service: "unknown",
        number: 33124,
    },
    PortDefinition {
        service: "unknown",
        number: 33087,
    },
    PortDefinition {
        service: "unknown",
        number: 33070,
    },
    PortDefinition {
        service: "unknown",
        number: 33017,
    },
    PortDefinition {
        service: "unknown",
        number: 33011,
    },
    PortDefinition {
        service: "unknown",
        number: 32976,
    },
    PortDefinition {
        service: "unknown",
        number: 32961,
    },
    PortDefinition {
        service: "unknown",
        number: 32960,
    },
    PortDefinition {
        service: "unknown",
        number: 32944,
    },
    PortDefinition {
        service: "unknown",
        number: 32932,
    },
    PortDefinition {
        service: "unknown",
        number: 32911,
    },
    PortDefinition {
        service: "unknown",
        number: 32910,
    },
    PortDefinition {
        service: "unknown",
        number: 32908,
    },
    PortDefinition {
        service: "unknown",
        number: 32905,
    },
    PortDefinition {
        service: "unknown",
        number: 32904,
    },
    PortDefinition {
        service: "unknown",
        number: 32898,
    },
    PortDefinition {
        service: "unknown",
        number: 32897,
    },
    PortDefinition {
        service: "unknown",
        number: 32888,
    },
    PortDefinition {
        service: "unknown",
        number: 32871,
    },
    PortDefinition {
        service: "unknown",
        number: 32869,
    },
    PortDefinition {
        service: "unknown",
        number: 32868,
    },
    PortDefinition {
        service: "unknown",
        number: 32858,
    },
    PortDefinition {
        service: "unknown",
        number: 32842,
    },
    PortDefinition {
        service: "unknown",
        number: 32837,
    },
    PortDefinition {
        service: "unknown",
        number: 32820,
    },
    PortDefinition {
        service: "unknown",
        number: 32815,
    },
    PortDefinition {
        service: "unknown",
        number: 32814,
    },
    PortDefinition {
        service: "unknown",
        number: 32807,
    },
    PortDefinition {
        service: "unknown",
        number: 32799,
    },
    PortDefinition {
        service: "unknown",
        number: 32798,
    },
    PortDefinition {
        service: "unknown",
        number: 32797,
    },
    PortDefinition {
        service: "unknown",
        number: 32790,
    },
    PortDefinition {
        service: "unknown",
        number: 32789,
    },
    PortDefinition {
        service: "unknown",
        number: 32788,
    },
    PortDefinition {
        service: "unknown",
        number: 32765,
    },
    PortDefinition {
        service: "unknown",
        number: 32764,
    },
    PortDefinition {
        service: "unknown",
        number: 32261,
    },
    PortDefinition {
        service: "unknown",
        number: 32260,
    },
    PortDefinition {
        service: "unknown",
        number: 32219,
    },
    PortDefinition {
        service: "unknown",
        number: 32200,
    },
    PortDefinition {
        service: "unknown",
        number: 32102,
    },
    PortDefinition {
        service: "unknown",
        number: 32088,
    },
    PortDefinition {
        service: "unknown",
        number: 32031,
    },
    PortDefinition {
        service: "unknown",
        number: 32022,
    },
    PortDefinition {
        service: "unknown",
        number: 32006,
    },
    PortDefinition {
        service: "unknown",
        number: 31728,
    },
    PortDefinition {
        service: "unknown",
        number: 31657,
    },
    PortDefinition {
        service: "unknown",
        number: 31522,
    },
    PortDefinition {
        service: "unknown",
        number: 31438,
    },
    PortDefinition {
        service: "unknown",
        number: 31386,
    },
    PortDefinition {
        service: "unknown",
        number: 31339,
    },
    PortDefinition {
        service: "unknown",
        number: 31072,
    },
    PortDefinition {
        service: "unknown",
        number: 31058,
    },
    PortDefinition {
        service: "unknown",
        number: 31033,
    },
    PortDefinition {
        service: "unknown",
        number: 30896,
    },
    PortDefinition {
        service: "unknown",
        number: 30705,
    },
    PortDefinition {
        service: "unknown",
        number: 30659,
    },
    PortDefinition {
        service: "unknown",
        number: 30644,
    },
    PortDefinition {
        service: "unknown",
        number: 30599,
    },
    PortDefinition {
        service: "unknown",
        number: 30519,
    },
    PortDefinition {
        service: "unknown",
        number: 30299,
    },
    PortDefinition {
        service: "unknown",
        number: 30195,
    },
    PortDefinition {
        service: "unknown",
        number: 30087,
    },
    PortDefinition {
        service: "unknown",
        number: 29810,
    },
    PortDefinition {
        service: "unknown",
        number: 29507,
    },
    PortDefinition {
        service: "unknown",
        number: 29243,
    },
    PortDefinition {
        service: "unknown",
        number: 29152,
    },
    PortDefinition {
        service: "unknown",
        number: 29045,
    },
    PortDefinition {
        service: "unknown",
        number: 28967,
    },
    PortDefinition {
        service: "unknown",
        number: 28924,
    },
    PortDefinition {
        service: "unknown",
        number: 28851,
    },
    PortDefinition {
        service: "unknown",
        number: 28850,
    },
    PortDefinition {
        service: "unknown",
        number: 28717,
    },
    PortDefinition {
        service: "unknown",
        number: 28567,
    },
    PortDefinition {
        service: "unknown",
        number: 28374,
    },
    PortDefinition {
        service: "unknown",
        number: 28142,
    },
    PortDefinition {
        service: "unknown",
        number: 28114,
    },
    PortDefinition {
        service: "unknown",
        number: 27770,
    },
    PortDefinition {
        service: "unknown",
        number: 27537,
    },
    PortDefinition {
        service: "unknown",
        number: 27521,
    },
    PortDefinition {
        service: "unknown",
        number: 27372,
    },
    PortDefinition {
        service: "unknown",
        number: 27351,
    },
    PortDefinition {
        service: "unknown",
        number: 27350,
    },
    PortDefinition {
        service: "unknown",
        number: 27316,
    },
    PortDefinition {
        service: "unknown",
        number: 27204,
    },
    PortDefinition {
        service: "unknown",
        number: 27087,
    },
    PortDefinition {
        service: "unknown",
        number: 27075,
    },
    PortDefinition {
        service: "unknown",
        number: 27074,
    },
    PortDefinition {
        service: "unknown",
        number: 27055,
    },
    PortDefinition {
        service: "unknown",
        number: 27016,
    },
    PortDefinition {
        service: "unknown",
        number: 27015,
    },
    PortDefinition {
        service: "unknown",
        number: 26972,
    },
    PortDefinition {
        service: "unknown",
        number: 26669,
    },
    PortDefinition {
        service: "unknown",
        number: 26417,
    },
    PortDefinition {
        service: "unknown",
        number: 26340,
    },
    PortDefinition {
        service: "unknown",
        number: 26007,
    },
    PortDefinition {
        service: "unknown",
        number: 26001,
    },
    PortDefinition {
        service: "unknown",
        number: 25847,
    },
    PortDefinition {
        service: "unknown",
        number: 25717,
    },
    PortDefinition {
        service: "unknown",
        number: 25703,
    },
    PortDefinition {
        service: "unknown",
        number: 25486,
    },
    PortDefinition {
        service: "unknown",
        number: 25473,
    },
    PortDefinition {
        service: "unknown",
        number: 25445,
    },
    PortDefinition {
        service: "unknown",
        number: 25327,
    },
    PortDefinition {
        service: "unknown",
        number: 25288,
    },
    PortDefinition {
        service: "unknown",
        number: 25262,
    },
    PortDefinition {
        service: "unknown",
        number: 25260,
    },
    PortDefinition {
        service: "unknown",
        number: 25174,
    },
    PortDefinition {
        service: "unknown",
        number: 24999,
    },
    PortDefinition {
        service: "unknown",
        number: 24616,
    },
    PortDefinition {
        service: "unknown",
        number: 24552,
    },
    PortDefinition {
        service: "unknown",
        number: 24416,
    },
    PortDefinition {
        service: "unknown",
        number: 24392,
    },
    PortDefinition {
        service: "unknown",
        number: 24218,
    },
    PortDefinition {
        service: "unknown",
        number: 23953,
    },
    PortDefinition {
        service: "unknown",
        number: 23887,
    },
    PortDefinition {
        service: "unknown",
        number: 23723,
    },
    PortDefinition {
        service: "unknown",
        number: 23451,
    },
    PortDefinition {
        service: "unknown",
        number: 23430,
    },
    PortDefinition {
        service: "unknown",
        number: 23382,
    },
    PortDefinition {
        service: "unknown",
        number: 23342,
    },
    PortDefinition {
        service: "unknown",
        number: 23296,
    },
    PortDefinition {
        service: "unknown",
        number: 23270,
    },
    PortDefinition {
        service: "unknown",
        number: 23228,
    },
    PortDefinition {
        service: "unknown",
        number: 23219,
    },
    PortDefinition {
        service: "unknown",
        number: 23040,
    },
    PortDefinition {
        service: "unknown",
        number: 23017,
    },
    PortDefinition {
        service: "unknown",
        number: 22969,
    },
    PortDefinition {
        service: "unknown",
        number: 22959,
    },
    PortDefinition {
        service: "unknown",
        number: 22882,
    },
    PortDefinition {
        service: "unknown",
        number: 22769,
    },
    PortDefinition {
        service: "unknown",
        number: 22727,
    },
    PortDefinition {
        service: "unknown",
        number: 22719,
    },
    PortDefinition {
        service: "unknown",
        number: 22711,
    },
    PortDefinition {
        service: "unknown",
        number: 22563,
    },
    PortDefinition {
        service: "unknown",
        number: 22341,
    },
    PortDefinition {
        service: "unknown",
        number: 22290,
    },
    PortDefinition {
        service: "unknown",
        number: 22223,
    },
    PortDefinition {
        service: "unknown",
        number: 22200,
    },
    PortDefinition {
        service: "unknown",
        number: 22177,
    },
    PortDefinition {
        service: "unknown",
        number: 22100,
    },
    PortDefinition {
        service: "unknown",
        number: 22063,
    },
    PortDefinition {
        service: "unknown",
        number: 22022,
    },
    PortDefinition {
        service: "unknown",
        number: 21915,
    },
    PortDefinition {
        service: "unknown",
        number: 21891,
    },
    PortDefinition {
        service: "unknown",
        number: 21728,
    },
    PortDefinition {
        service: "unknown",
        number: 21634,
    },
    PortDefinition {
        service: "unknown",
        number: 21631,
    },
    PortDefinition {
        service: "unknown",
        number: 21473,
    },
    PortDefinition {
        service: "unknown",
        number: 21078,
    },
    PortDefinition {
        service: "unknown",
        number: 21011,
    },
    PortDefinition {
        service: "unknown",
        number: 20990,
    },
    PortDefinition {
        service: "unknown",
        number: 20940,
    },
    PortDefinition {
        service: "unknown",
        number: 20934,
    },
    PortDefinition {
        service: "unknown",
        number: 20883,
    },
    PortDefinition {
        service: "unknown",
        number: 20734,
    },
    PortDefinition {
        service: "unknown",
        number: 20473,
    },
    PortDefinition {
        service: "unknown",
        number: 20280,
    },
    PortDefinition {
        service: "unknown",
        number: 20228,
    },
    PortDefinition {
        service: "unknown",
        number: 20227,
    },
    PortDefinition {
        service: "unknown",
        number: 20226,
    },
    PortDefinition {
        service: "unknown",
        number: 20225,
    },
    PortDefinition {
        service: "unknown",
        number: 20224,
    },
    PortDefinition {
        service: "unknown",
        number: 20223,
    },
    PortDefinition {
        service: "unknown",
        number: 20180,
    },
    PortDefinition {
        service: "unknown",
        number: 20179,
    },
    PortDefinition {
        service: "unknown",
        number: 20147,
    },
    PortDefinition {
        service: "unknown",
        number: 20127,
    },
    PortDefinition {
        service: "unknown",
        number: 20125,
    },
    PortDefinition {
        service: "unknown",
        number: 20118,
    },
    PortDefinition {
        service: "unknown",
        number: 20111,
    },
    PortDefinition {
        service: "unknown",
        number: 20106,
    },
    PortDefinition {
        service: "unknown",
        number: 20102,
    },
    PortDefinition {
        service: "unknown",
        number: 20089,
    },
    PortDefinition {
        service: "unknown",
        number: 20085,
    },
    PortDefinition {
        service: "unknown",
        number: 20080,
    },
    PortDefinition {
        service: "unknown",
        number: 20076,
    },
    PortDefinition {
        service: "unknown",
        number: 20052,
    },
    PortDefinition {
        service: "unknown",
        number: 20039,
    },
    PortDefinition {
        service: "unknown",
        number: 20032,
    },
    PortDefinition {
        service: "unknown",
        number: 20021,
    },
    PortDefinition {
        service: "unknown",
        number: 20017,
    },
    PortDefinition {
        service: "unknown",
        number: 20011,
    },
    PortDefinition {
        service: "unknown",
        number: 19996,
    },
    PortDefinition {
        service: "unknown",
        number: 19995,
    },
    PortDefinition {
        service: "unknown",
        number: 19852,
    },
    PortDefinition {
        service: "unknown",
        number: 19715,
    },
    PortDefinition {
        service: "unknown",
        number: 19634,
    },
    PortDefinition {
        service: "unknown",
        number: 19612,
    },
    PortDefinition {
        service: "unknown",
        number: 19501,
    },
    PortDefinition {
        service: "unknown",
        number: 19464,
    },
    PortDefinition {
        service: "unknown",
        number: 19403,
    },
    PortDefinition {
        service: "unknown",
        number: 19353,
    },
    PortDefinition {
        service: "unknown",
        number: 19201,
    },
    PortDefinition {
        service: "unknown",
        number: 19200,
    },
    PortDefinition {
        service: "unknown",
        number: 19130,
    },
    PortDefinition {
        service: "unknown",
        number: 19010,
    },
    PortDefinition {
        service: "unknown",
        number: 18962,
    },
    PortDefinition {
        service: "unknown",
        number: 18910,
    },
    PortDefinition {
        service: "unknown",
        number: 18887,
    },
    PortDefinition {
        service: "unknown",
        number: 18874,
    },
    PortDefinition {
        service: "unknown",
        number: 18669,
    },
    PortDefinition {
        service: "unknown",
        number: 18569,
    },
    PortDefinition {
        service: "unknown",
        number: 18517,
    },
    PortDefinition {
        service: "unknown",
        number: 18505,
    },
    PortDefinition {
        service: "unknown",
        number: 18439,
    },
    PortDefinition {
        service: "unknown",
        number: 18380,
    },
    PortDefinition {
        service: "unknown",
        number: 18337,
    },
    PortDefinition {
        service: "unknown",
        number: 18336,
    },
    PortDefinition {
        service: "unknown",
        number: 18231,
    },
    PortDefinition {
        service: "unknown",
        number: 18148,
    },
    PortDefinition {
        service: "unknown",
        number: 18080,
    },
    PortDefinition {
        service: "unknown",
        number: 18015,
    },
    PortDefinition {
        service: "unknown",
        number: 18012,
    },
    PortDefinition {
        service: "unknown",
        number: 17997,
    },
    PortDefinition {
        service: "unknown",
        number: 17985,
    },
    PortDefinition {
        service: "unknown",
        number: 17969,
    },
    PortDefinition {
        service: "unknown",
        number: 17867,
    },
    PortDefinition {
        service: "unknown",
        number: 17860,
    },
    PortDefinition {
        service: "unknown",
        number: 17802,
    },
    PortDefinition {
        service: "unknown",
        number: 17801,
    },
    PortDefinition {
        service: "unknown",
        number: 17715,
    },
    PortDefinition {
        service: "unknown",
        number: 17702,
    },
    PortDefinition {
        service: "unknown",
        number: 17701,
    },
    PortDefinition {
        service: "unknown",
        number: 17700,
    },
    PortDefinition {
        service: "unknown",
        number: 17413,
    },
    PortDefinition {
        service: "unknown",
        number: 17409,
    },
    PortDefinition {
        service: "unknown",
        number: 17255,
    },
    PortDefinition {
        service: "unknown",
        number: 17251,
    },
    PortDefinition {
        service: "unknown",
        number: 17129,
    },
    PortDefinition {
        service: "unknown",
        number: 17089,
    },
    PortDefinition {
        service: "unknown",
        number: 17070,
    },
    PortDefinition {
        service: "unknown",
        number: 17017,
    },
    PortDefinition {
        service: "unknown",
        number: 17016,
    },
    PortDefinition {
        service: "unknown",
        number: 16901,
    },
    PortDefinition {
        service: "unknown",
        number: 16845,
    },
    PortDefinition {
        service: "unknown",
        number: 16797,
    },
    PortDefinition {
        service: "unknown",
        number: 16725,
    },
    PortDefinition {
        service: "unknown",
        number: 16724,
    },
    PortDefinition {
        service: "unknown",
        number: 16723,
    },
    PortDefinition {
        service: "unknown",
        number: 16464,
    },
    PortDefinition {
        service: "unknown",
        number: 16372,
    },
    PortDefinition {
        service: "unknown",
        number: 16349,
    },
    PortDefinition {
        service: "unknown",
        number: 16297,
    },
    PortDefinition {
        service: "unknown",
        number: 16286,
    },
    PortDefinition {
        service: "unknown",
        number: 16283,
    },
    PortDefinition {
        service: "unknown",
        number: 16273,
    },
    PortDefinition {
        service: "unknown",
        number: 16270,
    },
    PortDefinition {
        service: "unknown",
        number: 16048,
    },
    PortDefinition {
        service: "unknown",
        number: 15915,
    },
    PortDefinition {
        service: "unknown",
        number: 15758,
    },
    PortDefinition {
        service: "unknown",
        number: 15730,
    },
    PortDefinition {
        service: "unknown",
        number: 15722,
    },
    PortDefinition {
        service: "unknown",
        number: 15677,
    },
    PortDefinition {
        service: "unknown",
        number: 15670,
    },
    PortDefinition {
        service: "unknown",
        number: 15646,
    },
    PortDefinition {
        service: "unknown",
        number: 15645,
    },
    PortDefinition {
        service: "unknown",
        number: 15631,
    },
    PortDefinition {
        service: "unknown",
        number: 15550,
    },
    PortDefinition {
        service: "unknown",
        number: 15448,
    },
    PortDefinition {
        service: "unknown",
        number: 15344,
    },
    PortDefinition {
        service: "unknown",
        number: 15317,
    },
    PortDefinition {
        service: "unknown",
        number: 15275,
    },
    PortDefinition {
        service: "unknown",
        number: 15191,
    },
    PortDefinition {
        service: "unknown",
        number: 15190,
    },
    PortDefinition {
        service: "unknown",
        number: 15145,
    },
    PortDefinition {
        service: "unknown",
        number: 15050,
    },
    PortDefinition {
        service: "unknown",
        number: 15005,
    },
    PortDefinition {
        service: "unknown",
        number: 14916,
    },
    PortDefinition {
        service: "unknown",
        number: 14891,
    },
    PortDefinition {
        service: "unknown",
        number: 14827,
    },
    PortDefinition {
        service: "unknown",
        number: 14733,
    },
    PortDefinition {
        service: "unknown",
        number: 14693,
    },
    PortDefinition {
        service: "unknown",
        number: 14545,
    },
    PortDefinition {
        service: "unknown",
        number: 14534,
    },
    PortDefinition {
        service: "unknown",
        number: 14444,
    },
    PortDefinition {
        service: "unknown",
        number: 14443,
    },
    PortDefinition {
        service: "unknown",
        number: 14418,
    },
    PortDefinition {
        service: "unknown",
        number: 14254,
    },
    PortDefinition {
        service: "unknown",
        number: 14237,
    },
    PortDefinition {
        service: "unknown",
        number: 14218,
    },
    PortDefinition {
        service: "unknown",
        number: 14147,
    },
    PortDefinition {
        service: "unknown",
        number: 13899,
    },
    PortDefinition {
        service: "unknown",
        number: 13846,
    },
    PortDefinition {
        service: "unknown",
        number: 13784,
    },
    PortDefinition {
        service: "unknown",
        number: 13766,
    },
    PortDefinition {
        service: "unknown",
        number: 13730,
    },
    PortDefinition {
        service: "unknown",
        number: 13723,
    },
    PortDefinition {
        service: "unknown",
        number: 13695,
    },
    PortDefinition {
        service: "unknown",
        number: 13580,
    },
    PortDefinition {
        service: "unknown",
        number: 13502,
    },
    PortDefinition {
        service: "unknown",
        number: 13359,
    },
    PortDefinition {
        service: "unknown",
        number: 13340,
    },
    PortDefinition {
        service: "unknown",
        number: 13318,
    },
    PortDefinition {
        service: "unknown",
        number: 13306,
    },
    PortDefinition {
        service: "unknown",
        number: 13265,
    },
    PortDefinition {
        service: "unknown",
        number: 13264,
    },
    PortDefinition {
        service: "unknown",
        number: 13261,
    },
    PortDefinition {
        service: "unknown",
        number: 13250,
    },
    PortDefinition {
        service: "unknown",
        number: 13229,
    },
    PortDefinition {
        service: "unknown",
        number: 13194,
    },
    PortDefinition {
        service: "unknown",
        number: 13193,
    },
    PortDefinition {
        service: "unknown",
        number: 13192,
    },
    PortDefinition {
        service: "unknown",
        number: 13188,
    },
    PortDefinition {
        service: "unknown",
        number: 13167,
    },
    PortDefinition {
        service: "unknown",
        number: 13149,
    },
    PortDefinition {
        service: "unknown",
        number: 13142,
    },
    PortDefinition {
        service: "unknown",
        number: 13140,
    },
    PortDefinition {
        service: "unknown",
        number: 13132,
    },
    PortDefinition {
        service: "unknown",
        number: 13130,
    },
    PortDefinition {
        service: "unknown",
        number: 13093,
    },
    PortDefinition {
        service: "unknown",
        number: 13017,
    },
    PortDefinition {
        service: "unknown",
        number: 12962,
    },
    PortDefinition {
        service: "unknown",
        number: 12955,
    },
    PortDefinition {
        service: "unknown",
        number: 12892,
    },
    PortDefinition {
        service: "unknown",
        number: 12891,
    },
    PortDefinition {
        service: "unknown",
        number: 12766,
    },
    PortDefinition {
        service: "unknown",
        number: 12702,
    },
    PortDefinition {
        service: "unknown",
        number: 12699,
    },
    PortDefinition {
        service: "unknown",
        number: 12414,
    },
    PortDefinition {
        service: "unknown",
        number: 12340,
    },
    PortDefinition {
        service: "unknown",
        number: 12296,
    },
    PortDefinition {
        service: "unknown",
        number: 12275,
    },
    PortDefinition {
        service: "unknown",
        number: 12271,
    },
    PortDefinition {
        service: "unknown",
        number: 12251,
    },
    PortDefinition {
        service: "unknown",
        number: 12243,
    },
    PortDefinition {
        service: "unknown",
        number: 12240,
    },
    PortDefinition {
        service: "unknown",
        number: 12225,
    },
    PortDefinition {
        service: "unknown",
        number: 12192,
    },
    PortDefinition {
        service: "unknown",
        number: 12171,
    },
    PortDefinition {
        service: "unknown",
        number: 12156,
    },
    PortDefinition {
        service: "unknown",
        number: 12146,
    },
    PortDefinition {
        service: "unknown",
        number: 12137,
    },
    PortDefinition {
        service: "unknown",
        number: 12132,
    },
    PortDefinition {
        service: "unknown",
        number: 12097,
    },
    PortDefinition {
        service: "unknown",
        number: 12096,
    },
    PortDefinition {
        service: "unknown",
        number: 12090,
    },
    PortDefinition {
        service: "unknown",
        number: 12080,
    },
    PortDefinition {
        service: "unknown",
        number: 12077,
    },
    PortDefinition {
        service: "unknown",
        number: 12034,
    },
    PortDefinition {
        service: "unknown",
        number: 12031,
    },
    PortDefinition {
        service: "unknown",
        number: 12019,
    },
    PortDefinition {
        service: "unknown",
        number: 11940,
    },
    PortDefinition {
        service: "unknown",
        number: 11863,
    },
    PortDefinition {
        service: "unknown",
        number: 11862,
    },
    PortDefinition {
        service: "unknown",
        number: 11813,
    },
    PortDefinition {
        service: "unknown",
        number: 11735,
    },
    PortDefinition {
        service: "unknown",
        number: 11697,
    },
    PortDefinition {
        service: "unknown",
        number: 11552,
    },
    PortDefinition {
        service: "unknown",
        number: 11401,
    },
    PortDefinition {
        service: "unknown",
        number: 11296,
    },
    PortDefinition {
        service: "unknown",
        number: 11288,
    },
    PortDefinition {
        service: "unknown",
        number: 11250,
    },
    PortDefinition {
        service: "unknown",
        number: 11224,
    },
    PortDefinition {
        service: "unknown",
        number: 11200,
    },
    PortDefinition {
        service: "unknown",
        number: 11180,
    },
    PortDefinition {
        service: "unknown",
        number: 11100,
    },
    PortDefinition {
        service: "unknown",
        number: 11089,
    },
    PortDefinition {
        service: "unknown",
        number: 11033,
    },
    PortDefinition {
        service: "unknown",
        number: 11032,
    },
    PortDefinition {
        service: "unknown",
        number: 11031,
    },
    PortDefinition {
        service: "unknown",
        number: 11026,
    },
    PortDefinition {
        service: "unknown",
        number: 11019,
    },
    PortDefinition {
        service: "unknown",
        number: 11007,
    },
    PortDefinition {
        service: "unknown",
        number: 11003,
    },
    PortDefinition {
        service: "unknown",
        number: 10900,
    },
    PortDefinition {
        service: "unknown",
        number: 10878,
    },
    PortDefinition {
        service: "unknown",
        number: 10852,
    },
    PortDefinition {
        service: "unknown",
        number: 10842,
    },
    PortDefinition {
        service: "unknown",
        number: 10754,
    },
    PortDefinition {
        service: "unknown",
        number: 10699,
    },
    PortDefinition {
        service: "unknown",
        number: 10602,
    },
    PortDefinition {
        service: "unknown",
        number: 10601,
    },
    PortDefinition {
        service: "unknown",
        number: 10567,
    },
    PortDefinition {
        service: "unknown",
        number: 10565,
    },
    PortDefinition {
        service: "unknown",
        number: 10556,
    },
    PortDefinition {
        service: "unknown",
        number: 10555,
    },
    PortDefinition {
        service: "unknown",
        number: 10554,
    },
    PortDefinition {
        service: "unknown",
        number: 10553,
    },
    PortDefinition {
        service: "unknown",
        number: 10552,
    },
    PortDefinition {
        service: "unknown",
        number: 10551,
    },
    PortDefinition {
        service: "unknown",
        number: 10550,
    },
    PortDefinition {
        service: "unknown",
        number: 10535,
    },
    PortDefinition {
        service: "unknown",
        number: 10529,
    },
    PortDefinition {
        service: "unknown",
        number: 10509,
    },
    PortDefinition {
        service: "unknown",
        number: 10494,
    },
    PortDefinition {
        service: "unknown",
        number: 10414,
    },
    PortDefinition {
        service: "unknown",
        number: 10387,
    },
    PortDefinition {
        service: "unknown",
        number: 10357,
    },
    PortDefinition {
        service: "unknown",
        number: 10347,
    },
    PortDefinition {
        service: "unknown",
        number: 10338,
    },
    PortDefinition {
        service: "unknown",
        number: 10280,
    },
    PortDefinition {
        service: "unknown",
        number: 10255,
    },
    PortDefinition {
        service: "unknown",
        number: 10246,
    },
    PortDefinition {
        service: "unknown",
        number: 10245,
    },
    PortDefinition {
        service: "unknown",
        number: 10238,
    },
    PortDefinition {
        service: "unknown",
        number: 10093,
    },
    PortDefinition {
        service: "unknown",
        number: 10064,
    },
    PortDefinition {
        service: "unknown",
        number: 10045,
    },
    PortDefinition {
        service: "unknown",
        number: 10042,
    },
    PortDefinition {
        service: "unknown",
        number: 10035,
    },
    PortDefinition {
        service: "unknown",
        number: 10019,
    },
    PortDefinition {
        service: "unknown",
        number: 10018,
    },
    PortDefinition {
        service: "ultrex",
        number: 1327,
    },
    PortDefinition {
        service: "tscchat",
        number: 2330,
    },
    PortDefinition {
        service: "tributary",
        number: 2580,
    },
    PortDefinition {
        service: "tqdata",
        number: 2700,
    },
    PortDefinition {
        service: "tn-tl-fd2",
        number: 1584,
    },
    PortDefinition {
        service: "tambora",
        number: 9020,
    },
    PortDefinition {
        service: "sysopt",
        number: 3281,
    },
    PortDefinition {
        service: "sybasedbsynch",
        number: 2439,
    },
    PortDefinition {
        service: "swldy-sias",
        number: 1250,
    },
    PortDefinition {
        service: "stt",
        number: 1607,
    },
    PortDefinition {
        service: "street-stream",
        number: 1736,
    },
    PortDefinition {
        service: "streetperfect",
        number: 1330,
    },
    PortDefinition {
        service: "starschool",
        number: 2270,
    },
    PortDefinition {
        service: "sqdr",
        number: 2728,
    },
    PortDefinition {
        service: "spcsdlobby",
        number: 2888,
    },
    PortDefinition {
        service: "soniqsync",
        number: 3803,
    },
    PortDefinition {
        service: "soagateway",
        number: 5250,
    },
    PortDefinition {
        service: "sightline",
        number: 1645,
    },
    PortDefinition {
        service: "sftsrv",
        number: 1303,
    },
    PortDefinition {
        service: "servistaitsm",
        number: 3636,
    },
    PortDefinition {
        service: "servergraph",
        number: 1251,
    },
    PortDefinition {
        service: "serialgateway",
        number: 1243,
    },
    PortDefinition {
        service: "seagulllms",
        number: 1291,
    },
    PortDefinition {
        service: "sdproxy",
        number: 1297,
    },
    PortDefinition {
        service: "scol",
        number: 1200,
    },
    PortDefinition {
        service: "scientia-sdb",
        number: 1811,
    },
    PortDefinition {
        service: "saris",
        number: 4442,
    },
    PortDefinition {
        service: "sacred",
        number: 1118,
    },
    PortDefinition {
        service: "sabarsd",
        number: 8401,
    },
    PortDefinition {
        service: "rtcm-sc104",
        number: 2101,
    },
    PortDefinition {
        service: "rsom",
        number: 2889,
    },
    PortDefinition {
        service: "rrimwm",
        number: 1694,
    },
    PortDefinition {
        service: "roketz",
        number: 1730,
    },
    PortDefinition {
        service: "rhp-iibp",
        number: 1912,
    },
    PortDefinition {
        service: "remote-winsock",
        number: 1745,
    },
    PortDefinition {
        service: "remote-collab",
        number: 2250,
    },
    PortDefinition {
        service: "re-conn-proto",
        number: 1306,
    },
    PortDefinition {
        service: "rebol",
        number: 2997,
    },
    PortDefinition {
        service: "ratl",
        number: 2449,
    },
    PortDefinition {
        service: "qnts-orb",
        number: 1262,
    },
    PortDefinition {
        service: "pxc-splr",
        number: 4007,
    },
    PortDefinition {
        service: "pt2-discover",
        number: 1101,
    },
    PortDefinition {
        service: "propel-msgsys",
        number: 1268,
    },
    PortDefinition {
        service: "privatechat",
        number: 1735,
    },
    PortDefinition {
        service: "privateark",
        number: 1858,
    },
    PortDefinition {
        service: "prat",
        number: 1264,
    },
    PortDefinition {
        service: "pptconference",
        number: 1711,
    },
    PortDefinition {
        service: "pkagent",
        number: 3118,
    },
    PortDefinition {
        service: "piranha2",
        number: 4601,
    },
    PortDefinition {
        service: "pip",
        number: 1321,
    },
    PortDefinition {
        service: "picknfs",
        number: 1598,
    },
    PortDefinition {
        service: "pe-mike",
        number: 1305,
    },
    PortDefinition {
        service: "pammratc",
        number: 1632,
    },
    PortDefinition {
        service: "palace-4",
        number: 9995,
    },
    PortDefinition {
        service: "pacmand",
        number: 1307,
    },
    PortDefinition {
        service: "p2pq",
        number: 1981,
    },
    PortDefinition {
        service: "ovtopmd",
        number: 2532,
    },
    PortDefinition {
        service: "oracle-vp2",
        number: 1808,
    },
    PortDefinition {
        service: "optilogic",
        number: 2435,
    },
    PortDefinition {
        service: "openvpn",
        number: 1194,
    },
    PortDefinition {
        service: "ontime",
        number: 1622,
    },
    PortDefinition {
        service: "nmsd",
        number: 1239,
    },
    PortDefinition {
        service: "netrisk",
        number: 1799,
    },
    PortDefinition {
        service: "ndtp",
        number: 2882,
    },
    PortDefinition {
        service: "ncpm-hip",
        number: 1683,
    },
    PortDefinition {
        service: "ncadg-ip-udp",
        number: 3063,
    },
    PortDefinition {
        service: "ncacn-ip-tcp",
        number: 3062,
    },
    PortDefinition {
        service: "naap",
        number: 1340,
    },
    PortDefinition {
        service: "n1-rmgmt",
        number: 4447,
    },
    PortDefinition {
        service: "musiconline",
        number: 1806,
    },
    PortDefinition {
        service: "muse",
        number: 6888,
    },
    PortDefinition {
        service: "msp",
        number: 2438,
    },
    PortDefinition {
        service: "mpshrsv",
        number: 1261,
    },
    PortDefinition {
        service: "mppolicy-mgr",
        number: 5969,
    },
    PortDefinition {
        service: "mpidcmgr",
        number: 9343,
    },
    PortDefinition {
        service: "mon",
        number: 2583,
    },
    PortDefinition {
        service: "mobrien-chat",
        number: 2031,
    },
    PortDefinition {
        service: "minilock",
        number: 3798,
    },
    PortDefinition {
        service: "mikey",
        number: 2269,
    },
    PortDefinition {
        service: "microsan",
        number: 20001,
    },
    PortDefinition {
        service: "metricadbc",
        number: 2622,
    },
    PortDefinition {
        service: "metasys",
        number: 11001,
    },
    PortDefinition {
        service: "metasage",
        number: 1207,
    },
    PortDefinition {
        service: "metaconsole",
        number: 2850,
    },
    PortDefinition {
        service: "memcachedb",
        number: 21201,
    },
    PortDefinition {
        service: "mao",
        number: 2908,
    },
    PortDefinition {
        service: "mailprox",
        number: 3936,
    },
    PortDefinition {
        service: "magicnotes",
        number: 3023,
    },
    PortDefinition {
        service: "lnvpoller",
        number: 2280,
    },
    PortDefinition {
        service: "lmdp",
        number: 2623,
    },
    PortDefinition {
        service: "lazy-ptop",
        number: 7099,
    },
    PortDefinition {
        service: "lanmessenger",
        number: 2372,
    },
    PortDefinition {
        service: "krb5gatekeeper",
        number: 1318,
    },
    PortDefinition {
        service: "kjtsiteserver",
        number: 1339,
    },
    PortDefinition {
        service: "ivmanager",
        number: 1276,
    },
    PortDefinition {
        service: "irisa",
        number: 11000,
    },
    PortDefinition {
        service: "iqobject",
        number: 48619,
    },
    PortDefinition {
        service: "ipether232port",
        number: 3497,
    },
    PortDefinition {
        service: "ipcd3",
        number: 1209,
    },
    PortDefinition {
        service: "intersan",
        number: 1331,
    },
    PortDefinition {
        service: "instantia",
        number: 1240,
    },
    PortDefinition {
        service: "informer",
        number: 3856,
    },
    PortDefinition {
        service: "identify",
        number: 2987,
    },
    PortDefinition {
        service: "idcp",
        number: 2326,
    },
    PortDefinition {
        service: "icl-twobase2",
        number: 25001,
    },
    PortDefinition {
        service: "icl-twobase1",
        number: 25000,
    },
    PortDefinition {
        service: "ibm-dt-2",
        number: 1792,
    },
    PortDefinition {
        service: "hyperip",
        number: 3919,
    },
    PortDefinition {
        service: "hp-sci",
        number: 1299,
    },
    PortDefinition {
        service: "hpidsadmin",
        number: 2984,
    },
    PortDefinition {
        service: "houdini-lm",
        number: 1715,
    },
    PortDefinition {
        service: "hb-engine",
        number: 1703,
    },
    PortDefinition {
        service: "groupwise",
        number: 1677,
    },
    PortDefinition {
        service: "gnunet",
        number: 2086,
    },
    PortDefinition {
        service: "gat-lmd",
        number: 1708,
    },
    PortDefinition {
        service: "florence",
        number: 1228,
    },
    PortDefinition {
        service: "fintrx",
        number: 3787,
    },
    PortDefinition {
        service: "fcp-srvr-inst1",
        number: 5502,
    },
    PortDefinition {
        service: "faxportwinport",
        number: 1620,
    },
    PortDefinition {
        service: "exbit-escp",
        number: 1316,
    },
    PortDefinition {
        service: "ets",
        number: 1569,
    },
    PortDefinition {
        service: "eoss",
        number: 1210,
    },
    PortDefinition {
        service: "empire-empuma",
        number: 1691,
    },
    PortDefinition {
        service: "emperion",
        number: 1282,
    },
    PortDefinition {
        service: "elatelink",
        number: 2124,
    },
    PortDefinition {
        service: "ea1",
        number: 1791,
    },
    PortDefinition {
        service: "dynamic3d",
        number: 2150,
    },
    PortDefinition {
        service: "domaintime",
        number: 9909,
    },
    PortDefinition {
        service: "dnox",
        number: 4022,
    },
    PortDefinition {
        service: "delta-mcp",
        number: 1324,
    },
    PortDefinition {
        service: "cyaserv",
        number: 2584,
    },
    PortDefinition {
        service: "cvmmon",
        number: 2300,
    },
    PortDefinition {
        service: "cumulus",
        number: 9287,
    },
    PortDefinition {
        service: "cspuni",
        number: 2806,
    },
    PortDefinition {
        service: "corelvideo",
        number: 1566,
    },
    PortDefinition {
        service: "conferencetalk",
        number: 1713,
    },
    PortDefinition {
        service: "commonspace",
        number: 1592,
    },
    PortDefinition {
        service: "cimtrak",
        number: 3749,
    },
    PortDefinition {
        service: "ci3-software-2",
        number: 1302,
    },
    PortDefinition {
        service: "centra",
        number: 1709,
    },
    PortDefinition {
        service: "celatalk",
        number: 3485,
    },
    PortDefinition {
        service: "cas",
        number: 2418,
    },
    PortDefinition {
        service: "c3",
        number: 2472,
    },
    PortDefinition {
        service: "binkp",
        number: 24554,
    },
    PortDefinition {
        service: "bears-02",
        number: 3146,
    },
    PortDefinition {
        service: "avenue",
        number: 2134,
    },
    PortDefinition {
        service: "appliance-cfg",
        number: 2898,
    },
    PortDefinition {
        service: "apani2",
        number: 9161,
    },
    PortDefinition {
        service: "apani1",
        number: 9160,
    },
    PortDefinition {
        service: "amx-weblinx",
        number: 2930,
    },
    PortDefinition {
        service: "amx-icsp",
        number: 1319,
    },
    PortDefinition {
        service: "amp",
        number: 3811,
    },
    PortDefinition {
        service: "altav-remmgt",
        number: 2456,
    },
    PortDefinition {
        service: "allstorcns",
        number: 2901,
    },
    PortDefinition {
        service: "affiliate",
        number: 6579,
    },
    PortDefinition {
        service: "ads",
        number: 2550,
    },
    PortDefinition {
        service: "admind",
        number: 8403,
    },
    PortDefinition {
        service: "boinc",
        number: 31416,
    },
    PortDefinition {
        service: "wnn6",
        number: 22273,
    },
    PortDefinition {
        service: "afs3-volser",
        number: 7005,
    },
    PortDefinition {
        service: "sqlnet",
        number: 66,
    },
    PortDefinition {
        service: "sometimes-rpc27",
        number: 32787,
    },
    PortDefinition {
        service: "sometimes-rpc25",
        number: 32786,
    },
    PortDefinition {
        service: "silc",
        number: 706,
    },
    PortDefinition {
        service: "rlzdbase",
        number: 635,
    },
    PortDefinition {
        service: "isdninfo",
        number: 6105,
    },
    PortDefinition {
        service: "work-sol",
        number: 400,
    },
    PortDefinition {
        service: "ni-ftp",
        number: 47,
    },
    PortDefinition {
        service: "netconf-ssh",
        number: 830,
    },
    PortDefinition {
        service: "netcheque",
        number: 4008,
    },
    PortDefinition {
        service: "ncd-pref-tcp",
        number: 5977,
    },
    PortDefinition {
        service: "tr-rsrb-p3",
        number: 1989,
    },
    PortDefinition {
        service: "marcam-lm",
        number: 1444,
    },
    PortDefinition {
        service: "mapper-mapethd",
        number: 3985,
    },
    PortDefinition {
        service: "ggf-ncp",
        number: 678,
    },
    PortDefinition {
        service: "flexlm1",
        number: 27001,
    },
    PortDefinition {
        service: "http-alt",
        number: 591,
    },
    PortDefinition {
        service: "esro-emsdp",
        number: 642,
    },
    PortDefinition {
        service: "ddm-rdb",
        number: 446,
    },
    PortDefinition {
        service: "cadis-1",
        number: 1441,
    },
    PortDefinition {
        service: "bo2k",
        number: 54320,
    },
    PortDefinition {
        service: "systat",
        number: 11,
    },
    PortDefinition {
        service: "vid",
        number: 769,
    },
    PortDefinition {
        service: "unknown",
        number: 983,
    },
    PortDefinition {
        service: "unknown",
        number: 979,
    },
    PortDefinition {
        service: "unknown",
        number: 973,
    },
    PortDefinition {
        service: "unknown",
        number: 967,
    },
    PortDefinition {
        service: "unknown",
        number: 965,
    },
    PortDefinition {
        service: "unknown",
        number: 961,
    },
    PortDefinition {
        service: "unknown",
        number: 942,
    },
    PortDefinition {
        service: "unknown",
        number: 935,
    },
    PortDefinition {
        service: "unknown",
        number: 926,
    },
    PortDefinition {
        service: "unknown",
        number: 925,
    },
    PortDefinition {
        service: "unknown",
        number: 914,
    },
    PortDefinition {
        service: "unknown",
        number: 863,
    },
    PortDefinition {
        service: "unknown",
        number: 858,
    },
    PortDefinition {
        service: "unknown",
        number: 844,
    },
    PortDefinition {
        service: "unknown",
        number: 834,
    },
    PortDefinition {
        service: "unknown",
        number: 817,
    },
    PortDefinition {
        service: "unknown",
        number: 815,
    },
    PortDefinition {
        service: "unknown",
        number: 811,
    },
    PortDefinition {
        service: "unknown",
        number: 809,
    },
    PortDefinition {
        service: "unknown",
        number: 789,
    },
    PortDefinition {
        service: "unknown",
        number: 779,
    },
    PortDefinition {
        service: "unknown",
        number: 743,
    },
    PortDefinition {
        service: "unknown",
        number: 1019,
    },
    PortDefinition {
        service: "symplex",
        number: 1507,
    },
    PortDefinition {
        service: "stone-design-1",
        number: 1492,
    },
    PortDefinition {
        service: "snare",
        number: 509,
    },
    PortDefinition {
        service: "quotad",
        number: 762,
    },
    PortDefinition {
        service: "pcanywherestat",
        number: 5632,
    },
    PortDefinition {
        service: "ipdd",
        number: 578,
    },
    PortDefinition {
        service: "cvc",
        number: 1495,
    },
    PortDefinition {
        service: "cfengine",
        number: 5308,
    },
    PortDefinition {
        service: "xns-time",
        number: 52,
    },
    PortDefinition {
        service: "uarps",
        number: 219,
    },
    PortDefinition {
        service: "timed",
        number: 525,
    },
    PortDefinition {
        service: "timbuktu-srv4",
        number: 1420,
    },
    PortDefinition {
        service: "sun-dr",
        number: 665,
    },
    PortDefinition {
        service: "sco-websrvrmgr",
        number: 620,
    },
    PortDefinition {
        service: "dnet-tstproxy",
        number: 3064,
    },
    PortDefinition {
        service: "slnp",
        number: 3045,
    },
    PortDefinition {
        service: "repscmd",
        number: 653,
    },
    PortDefinition {
        service: "pcmail-srv",
        number: 158,
    },
    PortDefinition {
        service: "pana",
        number: 716,
    },
    PortDefinition {
        service: "owamp-control",
        number: 861,
    },
    PortDefinition {
        service: "issa",
        number: 9991,
    },
    PortDefinition {
        service: "cfs",
        number: 3049,
    },
    PortDefinition {
        service: "netware-csp",
        number: 1366,
    },
    PortDefinition {
        service: "ndm-server",
        number: 1364,
    },
    PortDefinition {
        service: "netconfsoapbeep",
        number: 833,
    },
    PortDefinition {
        service: "mit-dov",
        number: 91,
    },
    PortDefinition {
        service: "CarbonCopy",
        number: 1680,
    },
    PortDefinition {
        service: "sapcomm",
        number: 3398,
    },
    PortDefinition {
        service: "kerberos",
        number: 750,
    },
    PortDefinition {
        service: "sco-inetmgr",
        number: 615,
    },
    PortDefinition {
        service: "mnotes",
        number: 603,
    },
    PortDefinition {
        service: "softcm",
        number: 6110,
    },
    PortDefinition {
        service: "hostname",
        number: 101,
    },
    PortDefinition {
        service: "ftps-data",
        number: 989,
    },
    PortDefinition {
        service: "flexlm10",
        number: 27010,
    },
    PortDefinition {
        service: "fcp",
        number: 510,
    },
    PortDefinition {
        service: "fcp-udp",
        number: 810,
    },
    PortDefinition {
        service: "cce3x",
        number: 1139,
    },
    PortDefinition {
        service: "eims-admin",
        number: 4199,
    },
    PortDefinition {
        service: "deos",
        number: 76,
    },
    PortDefinition {
        service: "dhcp-failover2",
        number: 847,
    },
    PortDefinition {
        service: "cadview-3d",
        number: 649,
    },
    PortDefinition {
        service: "borland-dsj",
        number: 707,
    },
    PortDefinition {
        service: "dhcpc",
        number: 68,
    },
    PortDefinition {
        service: "secure-aux-bus",
        number: 664,
    },
    PortDefinition {
        service: "as-servermap",
        number: 449,
    },
    PortDefinition {
        service: "priv-dial",
        number: 75,
    },
    PortDefinition {
        service: "acr-nema",
        number: 104,
    },
    PortDefinition {
        service: "3com-amp3",
        number: 629,
    },
    PortDefinition {
        service: "xnmp",
        number: 1652,
    },
    PortDefinition {
        service: "xfr",
        number: 682,
    },
    PortDefinition {
        service: "vnas",
        number: 577,
    },
    PortDefinition {
        service: "unknown",
        number: 985,
    },
    PortDefinition {
        service: "unknown",
        number: 984,
    },
    PortDefinition {
        service: "unknown",
        number: 974,
    },
    PortDefinition {
        service: "unknown",
        number: 958,
    },
    PortDefinition {
        service: "unknown",
        number: 952,
    },
    PortDefinition {
        service: "unknown",
        number: 949,
    },
    PortDefinition {
        service: "unknown",
        number: 946,
    },
    PortDefinition {
        service: "unknown",
        number: 923,
    },
    PortDefinition {
        service: "unknown",
        number: 916,
    },
    PortDefinition {
        service: "unknown",
        number: 899,
    },
    PortDefinition {
        service: "unknown",
        number: 897,
    },
    PortDefinition {
        service: "unknown",
        number: 894,
    },
    PortDefinition {
        service: "unknown",
        number: 889,
    },
    PortDefinition {
        service: "unknown",
        number: 835,
    },
    PortDefinition {
        service: "unknown",
        number: 824,
    },
    PortDefinition {
        service: "unknown",
        number: 814,
    },
    PortDefinition {
        service: "unknown",
        number: 807,
    },
    PortDefinition {
        service: "unknown",
        number: 804,
    },
    PortDefinition {
        service: "unknown",
        number: 798,
    },
    PortDefinition {
        service: "unknown",
        number: 733,
    },
    PortDefinition {
        service: "unknown",
        number: 727,
    },
    PortDefinition {
        service: "unknown",
        number: 237,
    },
    PortDefinition {
        service: "unknown",
        number: 12,
    },
    PortDefinition {
        service: "unknown",
        number: 10,
    },
    PortDefinition {
        service: "stmf",
        number: 501,
    },
    PortDefinition {
        service: "smakynet",
        number: 122,
    },
    PortDefinition {
        service: "sgcp",
        number: 440,
    },
    PortDefinition {
        service: "rtip",
        number: 771,
    },
    PortDefinition {
        service: "netview-aix-3",
        number: 1663,
    },
    PortDefinition {
        service: "itm-mcell-s",
        number: 828,
    },
    PortDefinition {
        service: "iscsi",
        number: 860,
    },
    PortDefinition {
        service: "ieee-mms-ssl",
        number: 695,
    },
    PortDefinition {
        service: "ginad",
        number: 634,
    },
    PortDefinition {
        service: "gdomap",
        number: 538,
    },
    PortDefinition {
        service: "ftsrv",
        number: 1359,
    },
    PortDefinition {
        service: "connlcli",
        number: 1358,
    },
    PortDefinition {
        service: "vpac",
        number: 1517,
    },
    PortDefinition {
        service: "us-gv",
        number: 1370,
    },
    PortDefinition {
        service: "udt_os",
        number: 3900,
    },
    PortDefinition {
        service: "ticf-1",
        number: 492,
    },
    PortDefinition {
        service: "td-replica",
        number: 268,
    },
    PortDefinition {
        service: "subseven",
        number: 27374,
    },
    PortDefinition {
        service: "soap-beep",
        number: 605,
    },
    PortDefinition {
        service: "slnp",
        number: 8076,
    },
    PortDefinition {
        service: "shiva_confsrvr",
        number: 1651,
    },
    PortDefinition {
        service: "skkserv",
        number: 1178,
    },
    PortDefinition {
        service: "crystalenterprise",
        number: 6401,
    },
    PortDefinition {
        service: "kpasswd",
        number: 761,
    },
    PortDefinition {
        service: "rmonitor_secure",
        number: 5145,
    },
    PortDefinition {
        service: "re-mail-ck",
        number: 50,
    },
    PortDefinition {
        service: "terminaldb",
        number: 2018,
    },
    PortDefinition {
        service: "sbook",
        number: 1349,
    },
    PortDefinition {
        service: "troff",
        number: 2014,
    },
    PortDefinition {
        service: "qaz",
        number: 7597,
    },
    PortDefinition {
        service: "kauth",
        number: 2120,
    },
    PortDefinition {
        service: "proxima-lm",
        number: 1445,
    },
    PortDefinition {
        service: "prm-sm-np",
        number: 1402,
    },
    PortDefinition {
        service: "pipes",
        number: 1465,
    },
    PortDefinition {
        service: "jetdirect",
        number: 9104,
    },
    PortDefinition {
        service: "passgo-tivoli",
        number: 627,
    },
    PortDefinition {
        service: "mosmig",
        number: 4660,
    },
    PortDefinition {
        service: "openmanage",
        number: 7273,
    },
    PortDefinition {
        service: "oftep-rpc",
        number: 950,
    },
    PortDefinition {
        service: "os-licman",
        number: 1384,
    },
    PortDefinition {
        service: "objective-dbc",
        number: 1388,
    },
    PortDefinition {
        service: "krbupdate",
        number: 760,
    },
    PortDefinition {
        service: "npp",
        number: 92,
    },
    PortDefinition {
        service: "netconf-beep",
        number: 831,
    },
    PortDefinition {
        service: "ncd-diag-tcp",
        number: 5978,
    },
    PortDefinition {
        service: "fax",
        number: 4557,
    },
    PortDefinition {
        service: "mpm",
        number: 45,
    },
    PortDefinition {
        service: "mcidas",
        number: 112,
    },
    PortDefinition {
        service: "macon",
        number: 456,
    },
    PortDefinition {
        service: "fasttrack",
        number: 1214,
    },
    PortDefinition {
        service: "sj3",
        number: 3086,
    },
    PortDefinition {
        service: "iris-beep",
        number: 702,
    },
    PortDefinition {
        service: "irc",
        number: 6665,
    },
    PortDefinition {
        service: "igi-lm",
        number: 1404,
    },
    PortDefinition {
        service: "ieee-mms",
        number: 651,
    },
    PortDefinition {
        service: "hacl-hb",
        number: 5300,
    },
    PortDefinition {
        service: "gnutella2",
        number: 6347,
    },
    PortDefinition {
        service: "pcduo-old",
        number: 5400,
    },
    PortDefinition {
        service: "iclpv-dm",
        number: 1389,
    },
    PortDefinition {
        service: "dhcp-failover",
        number: 647,
    },
    PortDefinition {
        service: "ddm-ssl",
        number: 448,
    },
    PortDefinition {
        service: "cuillamartin",
        number: 1356,
    },
    PortDefinition {
        service: "sgi-dgl",
        number: 5232,
    },
    PortDefinition {
        service: "confluent",
        number: 1484,
    },
    PortDefinition {
        service: "tserver",
        number: 450,
    },
    PortDefinition {
        service: "stun-p2",
        number: 1991,
    },
    PortDefinition {
        service: "tr-rsrb-p2",
        number: 1988,
    },
    PortDefinition {
        service: "cichild-lm",
        number: 1523,
    },
    PortDefinition {
        service: "cadkey-tablet",
        number: 1400,
    },
    PortDefinition {
        service: "cadkey-licman",
        number: 1399,
    },
    PortDefinition {
        service: "fln-spx",
        number: 221,
    },
    PortDefinition {
        service: "atex_elmd",
        number: 1385,
    },
    PortDefinition {
        service: "aol-1",
        number: 5191,
    },
    PortDefinition {
        service: "alta-ana-lm",
        number: 1346,
    },
    PortDefinition {
        service: "xinuexpansion4",
        number: 2024,
    },
    PortDefinition {
        service: "venus",
        number: 2430,
    },
    PortDefinition {
        service: "unknown",
        number: 988,
    },
    PortDefinition {
        service: "unknown",
        number: 962,
    },
    PortDefinition {
        service: "unknown",
        number: 948,
    },
    PortDefinition {
        service: "unknown",
        number: 945,
    },
    PortDefinition {
        service: "unknown",
        number: 941,
    },
    PortDefinition {
        service: "unknown",
        number: 938,
    },
    PortDefinition {
        service: "unknown",
        number: 936,
    },
    PortDefinition {
        service: "unknown",
        number: 929,
    },
    PortDefinition {
        service: "unknown",
        number: 927,
    },
    PortDefinition {
        service: "unknown",
        number: 919,
    },
    PortDefinition {
        service: "unknown",
        number: 906,
    },
    PortDefinition {
        service: "unknown",
        number: 883,
    },
    PortDefinition {
        service: "unknown",
        number: 881,
    },
    PortDefinition {
        service: "unknown",
        number: 875,
    },
    PortDefinition {
        service: "unknown",
        number: 872,
    },
    PortDefinition {
        service: "unknown",
        number: 870,
    },
    PortDefinition {
        service: "unknown",
        number: 866,
    },
    PortDefinition {
        service: "unknown",
        number: 855,
    },
    PortDefinition {
        service: "unknown",
        number: 851,
    },
    PortDefinition {
        service: "unknown",
        number: 850,
    },
    PortDefinition {
        service: "unknown",
        number: 841,
    },
    PortDefinition {
        service: "unknown",
        number: 836,
    },
    PortDefinition {
        service: "unknown",
        number: 826,
    },
    PortDefinition {
        service: "unknown",
        number: 820,
    },
    PortDefinition {
        service: "unknown",
        number: 819,
    },
    PortDefinition {
        service: "unknown",
        number: 816,
    },
    PortDefinition {
        service: "unknown",
        number: 813,
    },
    PortDefinition {
        service: "unknown",
        number: 791,
    },
    PortDefinition {
        service: "unknown",
        number: 745,
    },
    PortDefinition {
        service: "unknown",
        number: 736,
    },
    PortDefinition {
        service: "unknown",
        number: 735,
    },
    PortDefinition {
        service: "unknown",
        number: 724,
    },
    PortDefinition {
        service: "unknown",
        number: 719,
    },
    PortDefinition {
        service: "unknown",
        number: 343,
    },
    PortDefinition {
        service: "unknown",
        number: 334,
    },
    PortDefinition {
        service: "unknown",
        number: 300,
    },
    PortDefinition {
        service: "unknown",
        number: 28,
    },
    PortDefinition {
        service: "unknown",
        number: 249,
    },
    PortDefinition {
        service: "unknown",
        number: 230,
    },
    PortDefinition {
        service: "unknown",
        number: 16,
    },
    PortDefinition {
        service: "unknown",
        number: 1018,
    },
    PortDefinition {
        service: "unknown",
        number: 1016,
    },
    PortDefinition {
        service: "tenfold",
        number: 658,
    },
    PortDefinition {
        service: "telefinder",
        number: 1474,
    },
    PortDefinition {
        service: "rushd",
        number: 696,
    },
    PortDefinition {
        service: "rda",
        number: 630,
    },
    PortDefinition {
        service: "purenoise",
        number: 663,
    },
    PortDefinition {
        service: "pehelp",
        number: 2307,
    },
    PortDefinition {
        service: "pciarray",
        number: 1552,
    },
    PortDefinition {
        service: "npmp-trap",
        number: 609,
    },
    PortDefinition {
        service: "netgw",
        number: 741,
    },
    PortDefinition {
        service: "ndsauth",
        number: 353,
    },
    PortDefinition {
        service: "mcns-sec",
        number: 638,
    },
    PortDefinition {
        service: "hecmtl-db",
        number: 1551,
    },
    PortDefinition {
        service: "hap",
        number: 661,
    },
    PortDefinition {
        service: "go-login",
        number: 491,
    },
    PortDefinition {
        service: "entrust-sps",
        number: 640,
    },
    PortDefinition {
        service: "crs",
        number: 507,
    },
    PortDefinition {
        service: "cimplex",
        number: 673,
    },
    PortDefinition {
        service: "bmpp",
        number: 632,
    },
    PortDefinition {
        service: "rightbrain",
        number: 1354,
    },
    PortDefinition {
        service: "jetdirect",
        number: 9105,
    },
    PortDefinition {
        service: "watershed-lm",
        number: 6143,
    },
    PortDefinition {
        service: "vpps-via",
        number: 676,
    },
    PortDefinition {
        service: "vmpwscs",
        number: 214,
    },
    PortDefinition {
        service: "bo2k",
        number: 14141,
    },
    PortDefinition {
        service: "audit",
        number: 182,
    },
    PortDefinition {
        service: "tftp",
        number: 69,
    },
    PortDefinition {
        service: "Trinoo_Master",
        number: 27665,
    },
    PortDefinition {
        service: "taligent-lm",
        number: 1475,
    },
    PortDefinition {
        service: "swift-rvf",
        number: 97,
    },
    PortDefinition {
        service: "servstat",
        number: 633,
    },
    PortDefinition {
        service: "rmonitor",
        number: 560,
    },
    PortDefinition {
        service: "controlit",
        number: 799,
    },
    PortDefinition {
        service: "afs3-rmtsys",
        number: 7009,
    },
    PortDefinition {
        service: "cypress",
        number: 2015,
    },
    PortDefinition {
        service: "qmqp",
        number: 628,
    },
    PortDefinition {
        service: "kerberos_master",
        number: 751,
    },
    PortDefinition {
        service: "proxy-plus",
        number: 4480,
    },
    PortDefinition {
        service: "prm-nm-np",
        number: 1403,
    },
    PortDefinition {
        service: "polipo",
        number: 8123,
    },
    PortDefinition {
        service: "tlisrv",
        number: 1527,
    },
    PortDefinition {
        service: "omfs",
        number: 723,
    },
    PortDefinition {
        service: "oceansoft-lm",
        number: 1466,
    },
    PortDefinition {
        service: "nms_topo_serv",
        number: 1486,
    },
    PortDefinition {
        service: "nkd",
        number: 1650,
    },
    PortDefinition {
        service: "nas",
        number: 991,
    },
    PortDefinition {
        service: "netconfsoaphttp",
        number: 832,
    },
    PortDefinition {
        service: "netbios-ns",
        number: 137,
    },
    PortDefinition {
        service: "bbn-mmx",
        number: 1348,
    },
    PortDefinition {
        service: "mdc-portmapper",
        number: 685,
    },
    PortDefinition {
        service: "landesk-rc",
        number: 1762,
    },
    PortDefinition {
        service: "carracho",
        number: 6701,
    },
    PortDefinition {
        service: "ircs",
        number: 994,
    },
    PortDefinition {
        service: "sae-urn",
        number: 4500,
    },
    PortDefinition {
        service: "irc",
        number: 194,
    },
    PortDefinition {
        service: "ris",
        number: 180,
    },
    PortDefinition {
        service: "intellistor-lm",
        number: 1539,
    },
    PortDefinition {
        service: "dbreporter",
        number: 1379,
    },
    PortDefinition {
        service: "la-maint",
        number: 51,
    },
    PortDefinition {
        service: "iclcnet-locate",
        number: 886,
    },
    PortDefinition {
        service: "dnet-keyproxy",
        number: 2064,
    },
    PortDefinition {
        service: "ibm-res",
        number: 1405,
    },
    PortDefinition {
        service: "ibm-cics",
        number: 1435,
    },
    PortDefinition {
        service: "pksd",
        number: 11371,
    },
    PortDefinition {
        service: "goldleaf-licman",
        number: 1401,
    },
    PortDefinition {
        service: "gv-us",
        number: 1369,
    },
    PortDefinition {
        service: "genie",
        number: 402,
    },
    PortDefinition {
        service: "gppitnp",
        number: 103,
    },
    PortDefinition {
        service: "fc-ser",
        number: 1372,
    },
    PortDefinition {
        service: "elcsd",
        number: 704,
    },
    PortDefinition {
        service: "dlep",
        number: 854,
    },
    PortDefinition {
        service: "seosload",
        number: 8892,
    },
    PortDefinition {
        service: "dbbrowse",
        number: 47557,
    },
    PortDefinition {
        service: "cryptoadmin",
        number: 624,
    },
    PortDefinition {
        service: "cadsi-lm",
        number: 1387,
    },
    PortDefinition {
        service: "saposs",
        number: 3397,
    },
    PortDefinition {
        service: "tr-rsrb-port",
        number: 1996,
    },
    PortDefinition {
        service: "perf-port",
        number: 1995,
    },
    PortDefinition {
        service: "gdp-port",
        number: 1997,
    },
    PortDefinition {
        service: "opsec-ufp",
        number: 18182,
    },
    PortDefinition {
        service: "opsec-lea",
        number: 18184,
    },
    PortDefinition {
        service: "ccmail",
        number: 3264,
    },
    PortDefinition {
        service: "meetingmaker",
        number: 3292,
    },
    PortDefinition {
        service: "netbackup",
        number: 13720,
    },
    PortDefinition {
        service: "jetdirect",
        number: 9107,
    },
    PortDefinition {
        service: "jetdirect",
        number: 9106,
    },
    PortDefinition {
        service: "at-rtmp",
        number: 201,
    },
    PortDefinition {
        service: "apple-licman",
        number: 1381,
    },
    PortDefinition {
        service: "priv-print",
        number: 35,
    },
    PortDefinition {
        service: "analogx",
        number: 6588,
    },
    PortDefinition {
        service: "sdserv",
        number: 5530,
    },
    PortDefinition {
        service: "vmodem",
        number: 3141,
    },
    PortDefinition {
        service: "vacdsm-sws",
        number: 670,
    },
    PortDefinition {
        service: "unknown",
        number: 970,
    },
    PortDefinition {
        service: "unknown",
        number: 968,
    },
    PortDefinition {
        service: "unknown",
        number: 964,
    },
    PortDefinition {
        service: "unknown",
        number: 963,
    },
    PortDefinition {
        service: "unknown",
        number: 960,
    },
    PortDefinition {
        service: "unknown",
        number: 959,
    },
    PortDefinition {
        service: "unknown",
        number: 951,
    },
    PortDefinition {
        service: "unknown",
        number: 947,
    },
    PortDefinition {
        service: "unknown",
        number: 944,
    },
    PortDefinition {
        service: "unknown",
        number: 939,
    },
    PortDefinition {
        service: "unknown",
        number: 933,
    },
    PortDefinition {
        service: "unknown",
        number: 909,
    },
    PortDefinition {
        service: "unknown",
        number: 895,
    },
    PortDefinition {
        service: "unknown",
        number: 891,
    },
    PortDefinition {
        service: "unknown",
        number: 879,
    },
    PortDefinition {
        service: "unknown",
        number: 869,
    },
    PortDefinition {
        service: "unknown",
        number: 868,
    },
    PortDefinition {
        service: "unknown",
        number: 867,
    },
    PortDefinition {
        service: "unknown",
        number: 837,
    },
    PortDefinition {
        service: "unknown",
        number: 821,
    },
    PortDefinition {
        service: "unknown",
        number: 812,
    },
    PortDefinition {
        service: "unknown",
        number: 797,
    },
    PortDefinition {
        service: "unknown",
        number: 796,
    },
    PortDefinition {
        service: "unknown",
        number: 794,
    },
    PortDefinition {
        service: "unknown",
        number: 788,
    },
    PortDefinition {
        service: "unknown",
        number: 756,
    },
    PortDefinition {
        service: "unknown",
        number: 734,
    },
    PortDefinition {
        service: "unknown",
        number: 721,
    },
    PortDefinition {
        service: "unknown",
        number: 718,
    },
    PortDefinition {
        service: "unknown",
        number: 708,
    },
    PortDefinition {
        service: "unknown",
        number: 703,
    },
    PortDefinition {
        service: "unknown",
        number: 60,
    },
    PortDefinition {
        service: "unknown",
        number: 40,
    },
    PortDefinition {
        service: "unknown",
        number: 253,
    },
    PortDefinition {
        service: "unknown",
        number: 231,
    },
    PortDefinition {
        service: "unknown",
        number: 14,
    },
    PortDefinition {
        service: "unknown",
        number: 1017,
    },
    PortDefinition {
        service: "unknown",
        number: 1003,
    },
    PortDefinition {
        service: "spmp",
        number: 656,
    },
    PortDefinition {
        service: "securenetpro-sensor",
        number: 975,
    },
    PortDefinition {
        service: "scrabble",
        number: 2026,
    },
    PortDefinition {
        service: "rfx-lm",
        number: 1497,
    },
    PortDefinition {
        service: "pirp",
        number: 553,
    },
    PortDefinition {
        service: "passgo",
        number: 511,
    },
    PortDefinition {
        service: "npmp-gui",
        number: 611,
    },
    PortDefinition {
        service: "nmap",
        number: 689,
    },
    PortDefinition {
        service: "netview-aix-8",
        number: 1668,
    },
    PortDefinition {
        service: "netview-aix-4",
        number: 1664,
    },
    PortDefinition {
        service: "netstat",
        number: 15,
    },
    PortDefinition {
        service: "monitor",
        number: 561,
    },
    PortDefinition {
        service: "maitrd",
        number: 997,
    },
    PortDefinition {
        service: "mailbox-lm",
        number: 505,
    },
    PortDefinition {
        service: "liberty-lm",
        number: 1496,
    },
    PortDefinition {
        service: "lanserver",
        number: 637,
    },
    PortDefinition {
        service: "ipx",
        number: 213,
    },
    PortDefinition {
        service: "innosys",
        number: 1412,
    },
    PortDefinition {
        service: "ifor-protocol",
        number: 1515,
    },
    PortDefinition {
        service: "hyperwave-isp",
        number: 692,
    },
    PortDefinition {
        service: "ha-cluster",
        number: 694,
    },
    PortDefinition {
        service: "entrust-aams",
        number: 681,
    },
    PortDefinition {
        service: "entrust-aaas",
        number: 680,
    },
    PortDefinition {
        service: "dwr",
        number: 644,
    },
    PortDefinition {
        service: "dctp",
        number: 675,
    },
    PortDefinition {
        service: "csdmbase",
        number: 1467,
    },
    PortDefinition {
        service: "contentserver",
        number: 454,
    },
    PortDefinition {
        service: "collaborator",
        number: 622,
    },
    PortDefinition {
        service: "clvm-cfg",
        number: 1476,
    },
    PortDefinition {
        service: "chromagrafx",
        number: 1373,
    },
    PortDefinition {
        service: "cadlock",
        number: 770,
    },
    PortDefinition {
        service: "arcisdms",
        number: 262,
    },
    PortDefinition {
        service: "aodv",
        number: 654,
    },
    PortDefinition {
        service: "ampr-info",
        number: 1535,
    },
    PortDefinition {
        service: "xns-mail",
        number: 58,
    },
    PortDefinition {
        service: "xdmcp",
        number: 177,
    },
    PortDefinition {
        service: "wnn6_DS",
        number: 26208,
    },
    PortDefinition {
        service: "vpp",
        number: 677,
    },
    PortDefinition {
        service: "vpvc",
        number: 1519,
    },
    PortDefinition {
        service: "video-activmail",
        number: 1398,
    },
    PortDefinition {
        service: "vat-control",
        number: 3457,
    },
    PortDefinition {
        service: "ups",
        number: 401,
    },
    PortDefinition {
        service: "synoptics-trap",
        number: 412,
    },
    PortDefinition {
        service: "ticf-2",
        number: 493,
    },
    PortDefinition {
        service: "netbackup",
        number: 13713,
    },
    PortDefinition {
        service: "objcall",
        number: 94,
    },
    PortDefinition {
        service: "watcom-sql",
        number: 1498,
    },
    PortDefinition {
        service: "supfilesrv",
        number: 871,
    },
    PortDefinition {
        service: "iclpv-sc",
        number: 1390,
    },
    PortDefinition {
        service: "statsci2-lm",
        number: 6145,
    },
    PortDefinition {
        service: "statsrv",
        number: 133,
    },
    PortDefinition {
        service: "srssend",
        number: 362,
    },
    PortDefinition {
        service: "sqlserv",
        number: 118,
    },
    PortDefinition {
        service: "srmp",
        number: 193,
    },
    PortDefinition {
        service: "sftp",
        number: 115,
    },
    PortDefinition {
        service: "shivahose",
        number: 1549,
    },
    PortDefinition {
        service: "afs3-update",
        number: 7008,
    },
    PortDefinition {
        service: "sift-uft",
        number: 608,
    },
    PortDefinition {
        service: "sas-2",
        number: 1436,
    },
    PortDefinition {
        service: "sas-1",
        number: 1426,
    },
    PortDefinition {
        service: "rap",
        number: 38,
    },
    PortDefinition {
        service: "netrjs-4",
        number: 74,
    },
    PortDefinition {
        service: "netrjs-3",
        number: 73,
    },
    PortDefinition {
        service: "netrjs-1",
        number: 71,
    },
    PortDefinition {
        service: "syslog-conn",
        number: 601,
    },
    PortDefinition {
        service: "profile",
        number: 136,
    },
    PortDefinition {
        service: "wincim",
        number: 4144,
    },
    PortDefinition {
        service: "pwdgen",
        number: 129,
    },
    PortDefinition {
        service: "overnet",
        number: 16444,
    },
    PortDefinition {
        service: "ora-lm",
        number: 1446,
    },
    PortDefinition {
        service: "nuts_dem",
        number: 4132,
    },
    PortDefinition {
        service: "novastorbakcup",
        number: 308,
    },
    PortDefinition {
        service: "mciautoreg",
        number: 1528,
    },
    PortDefinition {
        service: "adapt-sna",
        number: 1365,
    },
    PortDefinition {
        service: "iclpv-nls",
        number: 1393,
    },
    PortDefinition {
        service: "iclpv-nlc",
        number: 1394,
    },
    PortDefinition {
        service: "netmap_lm",
        number: 1493,
    },
    PortDefinition {
        service: "netbios-dgm",
        number: 138,
    },
    PortDefinition {
        service: "ncd-pref",
        number: 5997,
    },
    PortDefinition {
        service: "mptn",
        number: 397,
    },
    PortDefinition {
        service: "msg-icp",
        number: 29,
    },
    PortDefinition {
        service: "msg-auth",
        number: 31,
    },
    PortDefinition {
        service: "mpm-flags",
        number: 44,
    },
    PortDefinition {
        service: "webster",
        number: 2627,
    },
    PortDefinition {
        service: "montage-lm",
        number: 6147,
    },
    PortDefinition {
        service: "mvx-lm",
        number: 1510,
    },
    PortDefinition {
        service: "ms-shuttle",
        number: 568,
    },
    PortDefinition {
        service: "matip-type-a",
        number: 350,
    },
    PortDefinition {
        service: "knetd",
        number: 2053,
    },
    PortDefinition {
        service: "lonewolf-lm",
        number: 6146,
    },
    PortDefinition {
        service: "mythtv",
        number: 6544,
    },
    PortDefinition {
        service: "landesk-rc",
        number: 1763,
    },
    PortDefinition {
        service: "peerenabler",
        number: 3531,
    },
    PortDefinition {
        service: "iso-tsap-c2",
        number: 399,
    },
    PortDefinition {
        service: "sdsc-lm",
        number: 1537,
    },
    PortDefinition {
        service: "stun-p3",
        number: 1992,
    },
    PortDefinition {
        service: "intuitive-edge",
        number: 1355,
    },
    PortDefinition {
        service: "interhdl_elmd",
        number: 1454,
    },
    PortDefinition {
        service: "nsiiops",
        number: 261,
    },
    PortDefinition {
        service: "iclcnet_svinfo",
        number: 887,
    },
    PortDefinition {
        service: "src",
        number: 200,
    },
    PortDefinition {
        service: "ibm-pps",
        number: 1376,
    },
    PortDefinition {
        service: "hybrid",
        number: 1424,
    },
    PortDefinition {
        service: "spc",
        number: 6111,
    },
    PortDefinition {
        service: "hiq",
        number: 1410,
    },
    PortDefinition {
        service: "here-lm",
        number: 1409,
    },
    PortDefinition {
        service: "hcp-wismar",
        number: 686,
    },
    PortDefinition {
        service: "hacl-gs",
        number: 5301,
    },
    PortDefinition {
        service: "hacl-cfg",
        number: 5302,
    },
    PortDefinition {
        service: "fujitsu-dtc",
        number: 1513,
    },
    PortDefinition {
        service: "fujitsu-dev",
        number: 747,
    },
    PortDefinition {
        service: "tor-control",
        number: 9051,
    },
    PortDefinition {
        service: "fhc",
        number: 1499,
    },
    PortDefinition {
        service: "afs3-errors",
        number: 7006,
    },
    PortDefinition {
        service: "eicon-x25",
        number: 1439,
    },
    PortDefinition {
        service: "eicon-server",
        number: 1438,
    },
    PortDefinition {
        service: "apple-iphoto",
        number: 8770,
    },
    PortDefinition {
        service: "dn6-smm-red",
        number: 196,
    },
    PortDefinition {
        service: "domain-s",
        number: 853,
    },
    PortDefinition {
        service: "dcp",
        number: 93,
    },
    PortDefinition {
        service: "decladebug",
        number: 410,
    },
    PortDefinition {
        service: "datasurfsrvsec",
        number: 462,
    },
    PortDefinition {
        service: "compaq-evm",
        number: 619,
    },
    PortDefinition {
        service: "support",
        number: 1529,
    },
    PortDefinition {
        service: "stun-p1",
        number: 1990,
    },
    PortDefinition {
        service: "stun-port",
        number: 1994,
    },
    PortDefinition {
        service: "licensedaemon",
        number: 1986,
    },
    PortDefinition {
        service: "checksum",
        number: 1386,
    },
    PortDefinition {
        service: "opsec-sam",
        number: 18183,
    },
    PortDefinition {
        service: "opsec-cvp",
        number: 18181,
    },
    PortDefinition {
        service: "carracho",
        number: 6700,
    },
    PortDefinition {
        service: "cadis-2",
        number: 1442,
    },
    PortDefinition {
        service: "supdup",
        number: 95,
    },
    PortDefinition {
        service: "crystalreports",
        number: 6400,
    },
    PortDefinition {
        service: "blueberry-lm",
        number: 1432,
    },
    PortDefinition {
        service: "axon-lm",
        number: 1548,
    },
    PortDefinition {
        service: "sstats",
        number: 486,
    },
    PortDefinition {
        service: "autodesk-lm",
        number: 1422,
    },
    PortDefinition {
        service: "audionews",
        number: 114,
    },
    PortDefinition {
        service: "audio-activmail",
        number: 1397,
    },
    PortDefinition {
        service: "aspentec-lm",
        number: 6142,
    },
    PortDefinition {
        service: "apple-imap-admin",
        number: 626,
    },
    PortDefinition {
        service: "pcm",
        number: 1827,
    },
    PortDefinition {
        service: "ariel3",
        number: 422,
    },
    PortDefinition {
        service: "realm-rusd",
        number: 688,
    },
    PortDefinition {
        service: "at-zis",
        number: 206,
    },
    PortDefinition {
        service: "at-nbp",
        number: 202,
    },
    PortDefinition {
        service: "at-echo",
        number: 204,
    },
    PortDefinition {
        service: "afs",
        number: 1483,
    },
    PortDefinition {
        service: "rpasswd",
        number: 774,
    },
    PortDefinition {
        service: "accessnetwork",
        number: 699,
    },
    PortDefinition {
        service: "hddtemp",
        number: 7634,
    },
    PortDefinition {
        service: "xinuexpansion3",
        number: 2023,
    },
    PortDefinition {
        service: "wpages",
        number: 776,
    },
    PortDefinition {
        service: "vpps-qua",
        number: 672,
    },
    PortDefinition {
        service: "vistium-share",
        number: 1545,
    },
    PortDefinition {
        service: "venus-se",
        number: 2431,
    },
    PortDefinition {
        service: "uuidgen",
        number: 697,
    },
    PortDefinition {
        service: "unknown",
        number: 982,
    },
    PortDefinition {
        service: "unknown",
        number: 978,
    },
    PortDefinition {
        service: "unknown",
        number: 972,
    },
    PortDefinition {
        service: "unknown",
        number: 966,
    },
    PortDefinition {
        service: "unknown",
        number: 957,
    },
    PortDefinition {
        service: "unknown",
        number: 956,
    },
    PortDefinition {
        service: "unknown",
        number: 934,
    },
    PortDefinition {
        service: "unknown",
        number: 920,
    },
    PortDefinition {
        service: "unknown",
        number: 915,
    },
    PortDefinition {
        service: "unknown",
        number: 908,
    },
    PortDefinition {
        service: "unknown",
        number: 907,
    },
    PortDefinition {
        service: "unknown",
        number: 892,
    },
    PortDefinition {
        service: "unknown",
        number: 890,
    },
    PortDefinition {
        service: "unknown",
        number: 885,
    },
    PortDefinition {
        service: "unknown",
        number: 884,
    },
    PortDefinition {
        service: "unknown",
        number: 882,
    },
    PortDefinition {
        service: "unknown",
        number: 877,
    },
    PortDefinition {
        service: "unknown",
        number: 876,
    },
    PortDefinition {
        service: "unknown",
        number: 865,
    },
    PortDefinition {
        service: "unknown",
        number: 857,
    },
    PortDefinition {
        service: "unknown",
        number: 852,
    },
    PortDefinition {
        service: "unknown",
        number: 849,
    },
    PortDefinition {
        service: "unknown",
        number: 842,
    },
    PortDefinition {
        service: "unknown",
        number: 838,
    },
    PortDefinition {
        service: "unknown",
        number: 827,
    },
    PortDefinition {
        service: "unknown",
        number: 818,
    },
    PortDefinition {
        service: "unknown",
        number: 793,
    },
    PortDefinition {
        service: "unknown",
        number: 785,
    },
    PortDefinition {
        service: "unknown",
        number: 784,
    },
    PortDefinition {
        service: "unknown",
        number: 755,
    },
    PortDefinition {
        service: "unknown",
        number: 746,
    },
    PortDefinition {
        service: "unknown",
        number: 738,
    },
    PortDefinition {
        service: "unknown",
        number: 737,
    },
    PortDefinition {
        service: "unknown",
        number: 717,
    },
    PortDefinition {
        service: "unknown",
        number: 34,
    },
    PortDefinition {
        service: "unknown",
        number: 336,
    },
    PortDefinition {
        service: "unknown",
        number: 325,
    },
    PortDefinition {
        service: "unknown",
        number: 303,
    },
    PortDefinition {
        service: "unknown",
        number: 276,
    },
    PortDefinition {
        service: "unknown",
        number: 273,
    },
    PortDefinition {
        service: "unknown",
        number: 236,
    },
    PortDefinition {
        service: "unknown",
        number: 235,
    },
    PortDefinition {
        service: "unknown",
        number: 233,
    },
    PortDefinition {
        service: "unify",
        number: 181,
    },
    PortDefinition {
        service: "tunnel",
        number: 604,
    },
    PortDefinition {
        service: "timeflies",
        number: 1362,
    },
    PortDefinition {
        service: "tbrpf",
        number: 712,
    },
    PortDefinition {
        service: "tabula",
        number: 1437,
    },
    PortDefinition {
        service: "shadowserver",
        number: 2027,
    },
    PortDefinition {
        service: "screencast",
        number: 1368,
    },
    PortDefinition {
        service: "rap-listen",
        number: 1531,
    },
    PortDefinition {
        service: "pssc",
        number: 645,
    },
    PortDefinition {
        service: "pcanywhere",
        number: 65301,
    },
    PortDefinition {
        service: "openport",
        number: 260,
    },
    PortDefinition {
        service: "opalis-rdv",
        number: 536,
    },
    PortDefinition {
        service: "omserv",
        number: 764,
    },
    PortDefinition {
        service: "olsr",
        number: 698,
    },
    PortDefinition {
        service: "nqs",
        number: 607,
    },
    PortDefinition {
        service: "netview-aix-7",
        number: 1667,
    },
    PortDefinition {
        service: "netview-aix-2",
        number: 1662,
    },
    PortDefinition {
        service: "netview-aix-1",
        number: 1661,
    },
    PortDefinition {
        service: "nced",
        number: 404,
    },
    PortDefinition {
        service: "masqdialer",
        number: 224,
    },
    PortDefinition {
        service: "hyper-g",
        number: 418,
    },
    PortDefinition {
        service: "genrad-mux",
        number: 176,
    },
    PortDefinition {
        service: "gdoi",
        number: 848,
    },
    PortDefinition {
        service: "dpsi",
        number: 315,
    },
    PortDefinition {
        service: "digital-vrc",
        number: 466,
    },
    PortDefinition {
        service: "decap",
        number: 403,
    },
    PortDefinition {
        service: "dca",
        number: 1456,
    },
    PortDefinition {
        service: "dberegister",
        number: 1479,
    },
    PortDefinition {
        service: "datex-asn",
        number: 355,
    },
    PortDefinition {
        service: "cycleserv",
        number: 763,
    },
    PortDefinition {
        service: "csdm",
        number: 1472,
    },
    PortDefinition {
        service: "creativeserver",
        number: 453,
    },
    PortDefinition {
        service: "con",
        number: 759,
    },
    PortDefinition {
        service: "comscm",
        number: 437,
    },
    PortDefinition {
        service: "codasrv",
        number: 2432,
    },
    PortDefinition {
        service: "cfdptkt",
        number: 120,
    },
    PortDefinition {
        service: "bnet",
        number: 415,
    },
    PortDefinition {
        service: "aspeclmd",
        number: 1544,
    },
    PortDefinition {
        service: "3l-l1",
        number: 1511,
    },
    PortDefinition {
        service: "3ds-lm",
        number: 1538,
    },
    PortDefinition {
        service: "zserv",
        number: 346,
    },
    PortDefinition {
        service: "xyplex-mux",
        number: 173,
    },
    PortDefinition {
        service: "xns-ch",
        number: 54,
    },
    PortDefinition {
        service: "xns-auth",
        number: 56,
    },
    PortDefinition {
        service: "maybe-fw1",
        number: 265,
    },
    PortDefinition {
        service: "world-lm",
        number: 1462,
    },
    PortDefinition {
        service: "netbackup",
        number: 13701,
    },
    PortDefinition {
        service: "vpvd",
        number: 1518,
    },
    PortDefinition {
        service: "valisys-lm",
        number: 1457,
    },
    PortDefinition {
        service: "uucp-path",
        number: 117,
    },
    PortDefinition {
        service: "uaiact",
        number: 1470,
    },
    PortDefinition {
        service: "netbackup",
        number: 13715,
    },
    PortDefinition {
        service: "netbackup",
        number: 13714,
    },
    PortDefinition {
        service: "td-service",
        number: 267,
    },
    PortDefinition {
        service: "timbuktu-srv3",
        number: 1419,
    },
    PortDefinition {
        service: "timbuktu-srv2",
        number: 1418,
    },
    PortDefinition {
        service: "dbsa-lm",
        number: 1407,
    },
    PortDefinition {
        service: "is99s",
        number: 380,
    },
    PortDefinition {
        service: "tacacs-ds",
        number: 65,
    },
    PortDefinition {
        service: "synotics-relay",
        number: 391,
    },
    PortDefinition {
        service: "synotics-broker",
        number: 392,
    },
    PortDefinition {
        service: "smsp",
        number: 413,
    },
    PortDefinition {
        service: "iclpv-sas",
        number: 1391,
    },
    PortDefinition {
        service: "sshell",
        number: 614,
    },
    PortDefinition {
        service: "sophia-lm",
        number: 1408,
    },
    PortDefinition {
        service: "snmptrap",
        number: 162,
    },
    PortDefinition {
        service: "snagas",
        number: 108,
    },
    PortDefinition {
        service: "maybe-veritas",
        number: 4987,
    },
    PortDefinition {
        service: "shivadiscovery",
        number: 1502,
    },
    PortDefinition {
        service: "sco-websrvrmg3",
        number: 598,
    },
    PortDefinition {
        service: "scc-security",
        number: 582,
    },
    PortDefinition {
        service: "saft",
        number: 487,
    },
    PortDefinition {
        service: "courier",
        number: 530,
    },
    PortDefinition {
        service: "robcad-lm",
        number: 1509,
    },
    PortDefinition {
        service: "netrjs-2",
        number: 72,
    },
    PortDefinition {
        service: "rfa",
        number: 4672,
    },
    PortDefinition {
        service: "qft",
        number: 189,
    },
    PortDefinition {
        service: "tam",
        number: 209,
    },
    PortDefinition {
        service: "gist",
        number: 270,
    },
    PortDefinition {
        service: "pythonds",
        number: 7464,
    },
    PortDefinition {
        service: "prm-sm",
        number: 408,
    },
    PortDefinition {
        service: "prospero",
        number: 191,
    },
    PortDefinition {
        service: "proshare1",
        number: 1459,
    },
    PortDefinition {
        service: "prosharevideo",
        number: 5714,
    },
    PortDefinition {
        service: "prosharenotify",
        number: 5717,
    },
    PortDefinition {
        service: "proshareaudio",
        number: 5713,
    },
    PortDefinition {
        service: "9pfs",
        number: 564,
    },
    PortDefinition {
        service: "phonebook",
        number: 767,
    },
    PortDefinition {
        service: "philips-vc",
        number: 583,
    },
    PortDefinition {
        service: "iclpv-wsm",
        number: 1395,
    },
    PortDefinition {
        service: "osu-nms",
        number: 192,
    },
    PortDefinition {
        service: "oc-lm",
        number: 1448,
    },
    PortDefinition {
        service: "ocs_cmu",
        number: 428,
    },
    PortDefinition {
        service: "nuts_bootp",
        number: 4133,
    },
    PortDefinition {
        service: "novell-lu6.2",
        number: 1416,
    },
    PortDefinition {
        service: "submit",
        number: 773,
    },
    PortDefinition {
        service: "nrcabq-lm",
        number: 1458,
    },
    PortDefinition {
        service: "tempo",
        number: 526,
    },
    PortDefinition {
        service: "ndm-requester",
        number: 1363,
    },
    PortDefinition {
        service: "netrcs",
        number: 742,
    },
    PortDefinition {
        service: "msl_lmd",
        number: 1464,
    },
    PortDefinition {
        service: "mloadd",
        number: 1427,
    },
    PortDefinition {
        service: "miteksys-lm",
        number: 1482,
    },
    PortDefinition {
        service: "ms-rome",
        number: 569,
    },
    PortDefinition {
        service: "umeter",
        number: 571,
    },
    PortDefinition {
        service: "meta-corp",
        number: 6141,
    },
    PortDefinition {
        service: "matip-type-b",
        number: 351,
    },
    PortDefinition {
        service: "mapper-nodemgr",
        number: 3984,
    },
    PortDefinition {
        service: "connect-proxy",
        number: 5490,
    },
    PortDefinition {
        service: "compressnet",
        number: 2,
    },
    PortDefinition {
        service: "netbackup",
        number: 13718,
    },
    PortDefinition {
        service: "legent-1",
        number: 373,
    },
    PortDefinition {
        service: "kuang2",
        number: 17300,
    },
    PortDefinition {
        service: "kink",
        number: 910,
    },
    PortDefinition {
        service: "cronus",
        number: 148,
    },
    PortDefinition {
        service: "icb",
        number: 7326,
    },
    PortDefinition {
        service: "pt-tls",
        number: 271,
    },
    PortDefinition {
        service: "opc-job-start",
        number: 423,
    },
    PortDefinition {
        service: "infoman",
        number: 1451,
    },
    PortDefinition {
        service: "loadsrv",
        number: 480,
    },
    PortDefinition {
        service: "tpdu",
        number: 1430,
    },
    PortDefinition {
        service: "nms",
        number: 1429,
    },
    PortDefinition {
        service: "hp-collector",
        number: 781,
    },
    PortDefinition {
        service: "hp-alarm-mgr",
        number: 383,
    },
    PortDefinition {
        service: "hp-3000-telnet",
        number: 2564,
    },
    PortDefinition {
        service: "hmmp-op",
        number: 613,
    },
    PortDefinition {
        service: "hmmp-ind",
        number: 612,
    },
    PortDefinition {
        service: "hello-port",
        number: 652,
    },
    PortDefinition {
        service: "hacl-probe",
        number: 5303,
    },
    PortDefinition {
        service: "gwha",
        number: 1383,
    },
    PortDefinition {
        service: "gss-xlicen",
        number: 128,
    },
    PortDefinition {
        service: "gkrellm",
        number: 19150,
    },
    PortDefinition {
        service: "genie-lm",
        number: 1453,
    },
    PortDefinition {
        service: "gacp",
        number: 190,
    },
    PortDefinition {
        service: "funkproxy",
        number: 1505,
    },
    PortDefinition {
        service: "fc-cli",
        number: 1371,
    },
    PortDefinition {
        service: "netwall",
        number: 533,
    },
    PortDefinition {
        service: "flexlm9",
        number: 27009,
    },
    PortDefinition {
        service: "flexlm7",
        number: 27007,
    },
    PortDefinition {
        service: "flexlm5",
        number: 27005,
    },
    PortDefinition {
        service: "flexlm3",
        number: 27003,
    },
    PortDefinition {
        service: "flexlm2",
        number: 27002,
    },
    PortDefinition {
        service: "flexlm",
        number: 744,
    },
    PortDefinition {
        service: "essbase",
        number: 1423,
    },
    PortDefinition {
        service: "molly",
        number: 1374,
    },
    PortDefinition {
        service: "emfis-cntl",
        number: 141,
    },
    PortDefinition {
        service: "eicon-slp",
        number: 1440,
    },
    PortDefinition {
        service: "dvl-activemail",
        number: 1396,
    },
    PortDefinition {
        service: "dtag-ste-sb",
        number: 352,
    },
    PortDefinition {
        service: "dixie",
        number: 96,
    },
    PortDefinition {
        service: "auditd",
        number: 48,
    },
    PortDefinition {
        service: "deviceshare",
        number: 552,
    },
    PortDefinition {
        service: "meter",
        number: 570,
    },
    PortDefinition {
        service: "dbase",
        number: 217,
    },
    PortDefinition {
        service: "custix",
        number: 528,
    },
    PortDefinition {
        service: "sfs-config",
        number: 452,
    },
    PortDefinition {
        service: "sfs-smp-net",
        number: 451,
    },
    PortDefinition {
        service: "listen",
        number: 2766,
    },
    PortDefinition {
        service: "rkinit",
        number: 2108,
    },
    PortDefinition {
        service: "cisco-sys",
        number: 132,
    },
    PortDefinition {
        service: "snmp-tcp-port",
        number: 1993,
    },
    PortDefinition {
        service: "tr-rsrb-p1",
        number: 1987,
    },
    PortDefinition {
        service: "cisco-fna",
        number: 130,
    },
    PortDefinition {
        service: "opsec-ela",
        number: 18187,
    },
    PortDefinition {
        service: "atls",
        number: 216,
    },
    PortDefinition {
        service: "bmap",
        number: 3421,
    },
    PortDefinition {
        service: "bl-idm",
        number: 142,
    },
    PortDefinition {
        service: "netbackup",
        number: 13721,
    },
    PortDefinition {
        service: "dhcps",
        number: 67,
    },
    PortDefinition {
        service: "bo2k",
        number: 15151,
    },
    PortDefinition {
        service: "aurora-cmgr",
        number: 364,
    },
    PortDefinition {
        service: "af",
        number: 1411,
    },
    PortDefinition {
        service: "at-5",
        number: 205,
    },
    PortDefinition {
        service: "powerchuteplus",
        number: 6548,
    },
    PortDefinition {
        service: "ansatrader",
        number: 124,
    },
    PortDefinition {
        service: "ansanotify",
        number: 116,
    },
    PortDefinition {
        service: "aol-3",
        number: 5193,
    },
    PortDefinition {
        service: "fw1-mc-gui",
        number: 258,
    },
    PortDefinition {
        service: "powerburst",
        number: 485,
    },
    PortDefinition {
        service: "acp",
        number: 599,
    },
    PortDefinition {
        service: "aed-512",
        number: 149,
    },
    PortDefinition {
        service: "aal-lm",
        number: 1469,
    },
    PortDefinition {
        service: "entomb",
        number: 775,
    },
    PortDefinition {
        service: "whosockami",
        number: 2019,
    },
    PortDefinition {
        service: "ntalk",
        number: 518,
    },
    PortDefinition {
        service: "videotex",
        number: 516,
    },
    PortDefinition {
        service: "unknown",
        number: 986,
    },
    PortDefinition {
        service: "unknown",
        number: 977,
    },
    PortDefinition {
        service: "unknown",
        number: 976,
    },
    PortDefinition {
        service: "unknown",
        number: 955,
    },
    PortDefinition {
        service: "unknown",
        number: 954,
    },
    PortDefinition {
        service: "unknown",
        number: 937,
    },
    PortDefinition {
        service: "unknown",
        number: 932,
    },
    PortDefinition {
        service: "unknown",
        number: 896,
    },
    PortDefinition {
        service: "unknown",
        number: 893,
    },
    PortDefinition {
        service: "unknown",
        number: 845,
    },
    PortDefinition {
        service: "unknown",
        number: 8,
    },
    PortDefinition {
        service: "unknown",
        number: 768,
    },
    PortDefinition {
        service: "unknown",
        number: 766,
    },
    PortDefinition {
        service: "unknown",
        number: 739,
    },
    PortDefinition {
        service: "unknown",
        number: 337,
    },
    PortDefinition {
        service: "unknown",
        number: 329,
    },
    PortDefinition {
        service: "unknown",
        number: 326,
    },
    PortDefinition {
        service: "unknown",
        number: 305,
    },
    PortDefinition {
        service: "unknown",
        number: 295,
    },
    PortDefinition {
        service: "unknown",
        number: 294,
    },
    PortDefinition {
        service: "unknown",
        number: 293,
    },
    PortDefinition {
        service: "unknown",
        number: 289,
    },
    PortDefinition {
        service: "unknown",
        number: 288,
    },
    PortDefinition {
        service: "unknown",
        number: 277,
    },
    PortDefinition {
        service: "unknown",
        number: 238,
    },
    PortDefinition {
        service: "unknown",
        number: 234,
    },
    PortDefinition {
        service: "unknown",
        number: 229,
    },
    PortDefinition {
        service: "unknown",
        number: 228,
    },
    PortDefinition {
        service: "unknown",
        number: 226,
    },
    PortDefinition {
        service: "ulp",
        number: 522,
    },
    PortDefinition {
        service: "submitserver",
        number: 2028,
    },
    PortDefinition {
        service: "sql-net",
        number: 150,
    },
    PortDefinition {
        service: "sonar",
        number: 572,
    },
    PortDefinition {
        service: "smsd",
        number: 596,
    },
    PortDefinition {
        service: "smpte",
        number: 420,
    },
    PortDefinition {
        service: "skronk",
        number: 460,
    },
    PortDefinition {
        service: "simba-cs",
        number: 1543,
    },
    PortDefinition {
        service: "shrinkwrap",
        number: 358,
    },
    PortDefinition {
        service: "semantix",
        number: 361,
    },
    PortDefinition {
        service: "scx-proxy",
        number: 470,
    },
    PortDefinition {
        service: "scoi2odialog",
        number: 360,
    },
    PortDefinition {
        service: "scohelp",
        number: 457,
    },
    PortDefinition {
        service: "sanity",
        number: 643,
    },
    PortDefinition {
        service: "rtsps",
        number: 322,
    },
    PortDefinition {
        service: "rsvd",
        number: 168,
    },
    PortDefinition {
        service: "rrh",
        number: 753,
    },
    PortDefinition {
        service: "rpc2portmap",
        number: 369,
    },
    PortDefinition {
        service: "remote-kis",
        number: 185,
    },
    PortDefinition {
        service: "reachout",
        number: 43188,
    },
    PortDefinition {
        service: "rds2",
        number: 1541,
    },
    PortDefinition {
        service: "rds",
        number: 1540,
    },
    PortDefinition {
        service: "qrh",
        number: 752,
    },
    PortDefinition {
        service: "pim-rp-disc",
        number: 496,
    },
    PortDefinition {
        service: "pftp",
        number: 662,
    },
    PortDefinition {
        service: "peport",
        number: 1449,
    },
    PortDefinition {
        service: "pacerforum",
        number: 1480,
    },
    PortDefinition {
        service: "openmath",
        number: 1473,
    },
    PortDefinition {
        service: "ocserver",
        number: 184,
    },
    PortDefinition {
        service: "netview-aix-12",
        number: 1672,
    },
    PortDefinition {
        service: "netview-aix-11",
        number: 1671,
    },
    PortDefinition {
        service: "netview-aix-10",
        number: 1670,
    },
    PortDefinition {
        service: "mobilip-mn",
        number: 435,
    },
    PortDefinition {
        service: "mobileip-agent",
        number: 434,
    },
    PortDefinition {
        service: "miroconnect",
        number: 1532,
    },
    PortDefinition {
        service: "mimer",
        number: 1360,
    },
    PortDefinition {
        service: "mailq",
        number: 174,
    },
    PortDefinition {
        service: "ljk-login",
        number: 472,
    },
    PortDefinition {
        service: "linx",
        number: 1361,
    },
    PortDefinition {
        service: "isode-dua",
        number: 17007,
    },
    PortDefinition {
        service: "infoseek",
        number: 414,
    },
    PortDefinition {
        service: "iiop",
        number: 535,
    },
    PortDefinition {
        service: "iasd",
        number: 432,
    },
    PortDefinition {
        service: "iafserver",
        number: 479,
    },
    PortDefinition {
        service: "hybrid-pop",
        number: 473,
    },
    PortDefinition {
        service: "hems",
        number: 151,
    },
    PortDefinition {
        service: "gridgen-elmd",
        number: 1542,
    },
    PortDefinition {
        service: "dsfgw",
        number: 438,
    },
    PortDefinition {
        service: "docstor",
        number: 1488,
    },
    PortDefinition {
        service: "diagmond",
        number: 1508,
    },
    PortDefinition {
        service: "dei-icda",
        number: 618,
    },
    PortDefinition {
        service: "decauth",
        number: 316,
    },
    PortDefinition {
        service: "dcs",
        number: 1367,
    },
    PortDefinition {
        service: "dasp",
        number: 439,
    },
    PortDefinition {
        service: "corerjd",
        number: 284,
    },
    PortDefinition {
        service: "commerce",
        number: 542,
    },
    PortDefinition {
        service: "codaauth2",
        number: 370,
    },
    PortDefinition {
        service: "bootserver",
        number: 2016,
    },
    PortDefinition {
        service: "bhfhs",
        number: 248,
    },
    PortDefinition {
        service: "anynetgateway",
        number: 1491,
    },
    PortDefinition {
        service: "z-wave-tunnel",
        number: 44123,
    },
    PortDefinition {
        service: "z-wave-s",
        number: 41230,
    },
    PortDefinition {
        service: "zsecure",
        number: 7173,
    },
    PortDefinition {
        service: "filemq",
        number: 5670,
    },
    PortDefinition {
        service: "zmp",
        number: 3925,
    },
    PortDefinition {
        service: "zixi-transport",
        number: 7088,
    },
    PortDefinition {
        service: "zion-lm",
        number: 1425,
    },
    PortDefinition {
        service: "zigbee-ip",
        number: 17755,
    },
    PortDefinition {
        service: "zigbee-ips",
        number: 17756,
    },
    PortDefinition {
        service: "zieto-sock",
        number: 4072,
    },
    PortDefinition {
        service: "shiprush-d-ch",
        number: 5841,
    },
    PortDefinition {
        service: "zephyr-srv",
        number: 2102,
    },
    PortDefinition {
        service: "z-wave",
        number: 4123,
    },
    PortDefinition {
        service: "zarkov",
        number: 2989,
    },
    PortDefinition {
        service: "zabbix-trapper",
        number: 10051,
    },
    PortDefinition {
        service: "zabbix-agent",
        number: 10050,
    },
    PortDefinition {
        service: "racf",
        number: 18136,
    },
    PortDefinition {
        service: "yawn",
        number: 31029,
    },
    PortDefinition {
        service: "array-manager",
        number: 3726,
    },
    PortDefinition {
        service: "xybrid-rt",
        number: 9978,
    },
    PortDefinition {
        service: "xybrid-cloud",
        number: 9925,
    },
    PortDefinition {
        service: "xw-control",
        number: 36462,
    },
    PortDefinition {
        service: "xtreamx",
        number: 5793,
    },
    PortDefinition {
        service: "xtrm",
        number: 3423,
    },
    PortDefinition {
        service: "xtrms",
        number: 3424,
    },
    PortDefinition {
        service: "xtgui",
        number: 4095,
    },
    PortDefinition {
        service: "xss-srv-port",
        number: 3646,
    },
    PortDefinition {
        service: "xss-port",
        number: 3510,
    },
    PortDefinition {
        service: "xserveraid",
        number: 3722,
    },
    PortDefinition {
        service: "community",
        number: 2459,
    },
    PortDefinition {
        service: "xrpc-registry",
        number: 3651,
    },
    PortDefinition {
        service: "xpra",
        number: 14500,
    },
    PortDefinition {
        service: "xpl",
        number: 3865,
    },
    PortDefinition {
        service: "xpilot",
        number: 15345,
    },
    PortDefinition {
        service: "xo-wave",
        number: 3763,
    },
    PortDefinition {
        service: "xn-control",
        number: 38422,
    },
    PortDefinition {
        service: "xmpcr-interface",
        number: 3877,
    },
    PortDefinition {
        service: "XmlIpcRegSvc",
        number: 9092,
    },
    PortDefinition {
        service: "xkotodrcp",
        number: 5344,
    },
    PortDefinition {
        service: "xiostatus",
        number: 2341,
    },
    PortDefinition {
        service: "xtlserv",
        number: 6116,
    },
    PortDefinition {
        service: "xnds",
        number: 2157,
    },
    PortDefinition {
        service: "xns-courier",
        number: 165,
    },
    PortDefinition {
        service: "xsmsvc",
        number: 6936,
    },
    PortDefinition {
        service: "enguity-xccetp",
        number: 8041,
    },
    PortDefinition {
        service: "xcap-portal",
        number: 4888,
    },
    PortDefinition {
        service: "xcap-control",
        number: 4889,
    },
    PortDefinition {
        service: "xbox",
        number: 3074,
    },
    PortDefinition {
        service: "x-bone-api",
        number: 2165,
    },
    PortDefinition {
        service: "xandros-cms",
        number: 4389,
    },
    PortDefinition {
        service: "spramsd",
        number: 5770,
    },
    PortDefinition {
        service: "spramsca",
        number: 5769,
    },
    PortDefinition {
        service: "xoms",
        number: 16619,
    },
    PortDefinition {
        service: "xoraya",
        number: 11876,
    },
    PortDefinition {
        service: "x2e-disc",
        number: 11877,
    },
    PortDefinition {
        service: "x11",
        number: 6061,
    },
    PortDefinition {
        service: "x11",
        number: 6058,
    },
    PortDefinition {
        service: "x11",
        number: 6057,
    },
    PortDefinition {
        service: "x11",
        number: 6056,
    },
    PortDefinition {
        service: "x11",
        number: 6054,
    },
    PortDefinition {
        service: "x11",
        number: 6053,
    },
    PortDefinition {
        service: "x11",
        number: 6049,
    },
    PortDefinition {
        service: "x11",
        number: 6048,
    },
    PortDefinition {
        service: "x11",
        number: 6047,
    },
    PortDefinition {
        service: "x11",
        number: 6046,
    },
    PortDefinition {
        service: "x11",
        number: 6045,
    },
    PortDefinition {
        service: "x11",
        number: 6044,
    },
    PortDefinition {
        service: "x11",
        number: 6043,
    },
    PortDefinition {
        service: "x11",
        number: 6042,
    },
    PortDefinition {
        service: "x11",
        number: 6041,
    },
    PortDefinition {
        service: "x11",
        number: 6040,
    },
    PortDefinition {
        service: "x11",
        number: 6039,
    },
    PortDefinition {
        service: "x11",
        number: 6038,
    },
    PortDefinition {
        service: "x11",
        number: 6037,
    },
    PortDefinition {
        service: "x11",
        number: 6036,
    },
    PortDefinition {
        service: "x11",
        number: 6035,
    },
    PortDefinition {
        service: "x11",
        number: 6034,
    },
    PortDefinition {
        service: "x11",
        number: 6033,
    },
    PortDefinition {
        service: "x11",
        number: 6032,
    },
    PortDefinition {
        service: "x11",
        number: 6031,
    },
    PortDefinition {
        service: "x11",
        number: 6029,
    },
    PortDefinition {
        service: "x11",
        number: 6028,
    },
    PortDefinition {
        service: "x11",
        number: 6027,
    },
    PortDefinition {
        service: "x11",
        number: 6026,
    },
    PortDefinition {
        service: "x11",
        number: 6024,
    },
    PortDefinition {
        service: "x11",
        number: 6023,
    },
    PortDefinition {
        service: "x11",
        number: 6022,
    },
    PortDefinition {
        service: "x11",
        number: 6020,
    },
    PortDefinition {
        service: "x11",
        number: 6019,
    },
    PortDefinition {
        service: "x11",
        number: 6018,
    },
    PortDefinition {
        service: "x11",
        number: 6016,
    },
    PortDefinition {
        service: "x11",
        number: 6014,
    },
    PortDefinition {
        service: "x11",
        number: 6013,
    },
    PortDefinition {
        service: "x11",
        number: 6012,
    },
    PortDefinition {
        service: "x11",
        number: 6011,
    },
    PortDefinition {
        service: "wysdma",
        number: 3741,
    },
    PortDefinition {
        service: "wacp",
        number: 3633,
    },
    PortDefinition {
        service: "flirtmitmir",
        number: 3840,
    },
    PortDefinition {
        service: "wv-csp-udp-cir",
        number: 3717,
    },
    PortDefinition {
        service: "wv-csp-sms-cir",
        number: 3716,
    },
    PortDefinition {
        service: "wv-csp-sms",
        number: 3590,
    },
    PortDefinition {
        service: "wta-wsp-s",
        number: 2805,
    },
    PortDefinition {
        service: "wssauthsvc",
        number: 4537,
    },
    PortDefinition {
        service: "tungsten-http",
        number: 9762,
    },
    PortDefinition {
        service: "wsm-server-ssl",
        number: 5007,
    },
    PortDefinition {
        service: "wsm-server",
        number: 5006,
    },
    PortDefinition {
        service: "wsdl-event",
        number: 4879,
    },
    PortDefinition {
        service: "wsdapi-s",
        number: 5358,
    },
    PortDefinition {
        service: "wrspice",
        number: 6114,
    },
    PortDefinition {
        service: "wcpp",
        number: 4185,
    },
    PortDefinition {
        service: "www-dev",
        number: 2784,
    },
    PortDefinition {
        service: "blizwow",
        number: 3724,
    },
    PortDefinition {
        service: "worldfusion2",
        number: 2596,
    },
    PortDefinition {
        service: "worldfusion1",
        number: 2595,
    },
    PortDefinition {
        service: "workflowdir",
        number: 4417,
    },
    PortDefinition {
        service: "wcr-remlib",
        number: 4845,
    },
    PortDefinition {
        service: "wnn6_Tw",
        number: 22321,
    },
    PortDefinition {
        service: "wnn6_Cn",
        number: 22289,
    },
    PortDefinition {
        service: "wms-messenger",
        number: 3219,
    },
    PortDefinition {
        service: "wmc-log-svc",
        number: 1338,
    },
    PortDefinition {
        service: "wlcp",
        number: 36411,
    },
    PortDefinition {
        service: "winshadow-hd",
        number: 3861,
    },
    PortDefinition {
        service: "winpcs",
        number: 5166,
    },
    PortDefinition {
        service: "wininstall-ipc",
        number: 3674,
    },
    PortDefinition {
        service: "mm-admin",
        number: 534,
    },
    PortDefinition {
        service: "wsscomfrmwk",
        number: 6602,
    },
    PortDefinition {
        service: "winrm",
        number: 47001,
    },
    PortDefinition {
        service: "net-projection",
        number: 5363,
    },
    PortDefinition {
        service: "wcbackup",
        number: 8912,
    },
    PortDefinition {
        service: "windlm",
        number: 1785,
    },
    PortDefinition {
        service: "wimaxasncp",
        number: 2231,
    },
    PortDefinition {
        service: "tunatic",
        number: 5747,
    },
    PortDefinition {
        service: "tunalyzer",
        number: 5748,
    },
    PortDefinition {
        service: "wifree",
        number: 11208,
    },
    PortDefinition {
        service: "display",
        number: 7236,
    },
    PortDefinition {
        service: "wafs",
        number: 4049,
    },
    PortDefinition {
        service: "cisco-wafs",
        number: 4050,
    },
    PortDefinition {
        service: "WibuKey",
        number: 22347,
    },
    PortDefinition {
        service: "via-ftp",
        number: 63,
    },
    PortDefinition {
        service: "whisker",
        number: 3233,
    },
    PortDefinition {
        service: "wg-netforce",
        number: 3359,
    },
    PortDefinition {
        service: "dpp",
        number: 8908,
    },
    PortDefinition {
        service: "wello",
        number: 4177,
    },
    PortDefinition {
        service: "weandsf",
        number: 48050,
    },
    PortDefinition {
        service: "websphere-snmp",
        number: 3427,
    },
    PortDefinition {
        service: "bsfsvr-zn-ssl",
        number: 5321,
    },
    PortDefinition {
        service: "bsfserver-zn",
        number: 5320,
    },
    PortDefinition {
        service: "webmethods-b2b",
        number: 2907,
    },
    PortDefinition {
        service: "https-wmap",
        number: 8991,
    },
    PortDefinition {
        service: "http-wmap",
        number: 8990,
    },
    PortDefinition {
        service: "weblogin",
        number: 2054,
    },
    PortDefinition {
        service: "davsrcs",
        number: 9802,
    },
    PortDefinition {
        service: "davsrc",
        number: 9800,
    },
    PortDefinition {
        service: "wsynch",
        number: 3111,
    },
    PortDefinition {
        service: "ws-discovery",
        number: 3702,
    },
    PortDefinition {
        service: "wfc",
        number: 4847,
    },
    PortDefinition {
        service: "wxbrief",
        number: 4368,
    },
    PortDefinition {
        service: "wbem-exp-https",
        number: 5990,
    },
    PortDefinition {
        service: "watcomdebug",
        number: 3563,
    },
    PortDefinition {
        service: "watchdoc",
        number: 5744,
    },
    PortDefinition {
        service: "watchdoc-pod",
        number: 5743,
    },
    PortDefinition {
        service: "warehouse-sss",
        number: 12321,
    },
    PortDefinition {
        service: "warehouse",
        number: 12322,
    },
    PortDefinition {
        service: "wap-vcard-s",
        number: 9206,
    },
    PortDefinition {
        service: "wap-vcard",
        number: 9204,
    },
    PortDefinition {
        service: "wap-vcal",
        number: 9205,
    },
    PortDefinition {
        service: "wap-wsp-wtp",
        number: 9201,
    },
    PortDefinition {
        service: "wap-wsp-wtp-s",
        number: 9203,
    },
    PortDefinition {
        service: "wap-pushsecure",
        number: 2949,
    },
    PortDefinition {
        service: "wap-push",
        number: 2948,
    },
    PortDefinition {
        service: "wago-service",
        number: 6626,
    },
    PortDefinition {
        service: "3gpp-w1ap",
        number: 37472,
    },
    PortDefinition {
        service: "vvr-data",
        number: 8199,
    },
    PortDefinition {
        service: "vvr-control",
        number: 4145,
    },
    PortDefinition {
        service: "vulture",
        number: 3482,
    },
    PortDefinition {
        service: "vtu-comms",
        number: 2216,
    },
    PortDefinition {
        service: "netbackup",
        number: 13708,
    },
    PortDefinition {
        service: "upstriggervsw",
        number: 3786,
    },
    PortDefinition {
        service: "vsnm-agent",
        number: 3375,
    },
    PortDefinition {
        service: "vsi-omega",
        number: 7566,
    },
    PortDefinition {
        service: "vsiadmin",
        number: 2539,
    },
    PortDefinition {
        service: "vsamredirector",
        number: 2387,
    },
    PortDefinition {
        service: "vsaiport",
        number: 3317,
    },
    PortDefinition {
        service: "vrts-registry",
        number: 2410,
    },
    PortDefinition {
        service: "vrtp",
        number: 2255,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4299,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4296,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4295,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4293,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4292,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4291,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4290,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4289,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4288,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4287,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4286,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4285,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4284,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4283,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4282,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4281,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4280,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4278,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4277,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4276,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4275,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4274,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4273,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4272,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4271,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4270,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4269,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4268,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4267,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4266,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4265,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4264,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4263,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4261,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4260,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4259,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4258,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4257,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4256,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4255,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4254,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4253,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4251,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4250,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4249,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4248,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4247,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4246,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4245,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4244,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4241,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4240,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4239,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4238,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4237,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4236,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4235,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4233,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4232,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4231,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4230,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4229,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4228,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4227,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4226,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4225,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4223,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4222,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4221,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4219,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4218,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4217,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4216,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4215,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4214,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4213,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4212,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4211,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4210,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4209,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4208,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4207,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4205,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4204,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4203,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4202,
    },
    PortDefinition {
        service: "vrml-multi-use",
        number: 4201,
    },
    PortDefinition {
        service: "vrpn",
        number: 3883,
    },
    PortDefinition {
        service: "vrcommerce",
        number: 2530,
    },
    PortDefinition {
        service: "vpa",
        number: 5164,
    },
    PortDefinition {
        service: "voxelstorm",
        number: 28200,
    },
    PortDefinition {
        service: "v-one-spp",
        number: 3845,
    },
    PortDefinition {
        service: "voispeed-port",
        number: 3541,
    },
    PortDefinition {
        service: "interact",
        number: 4052,
    },
    PortDefinition {
        service: "vofr-gateway",
        number: 21590,
    },
    PortDefinition {
        service: "vocaltec-admin",
        number: 1796,
    },
    PortDefinition {
        service: "vocaltec-hos",
        number: 25793,
    },
    PortDefinition {
        service: "vnyx",
        number: 8699,
    },
    PortDefinition {
        service: "vmware-fdm",
        number: 8182,
    },
    PortDefinition {
        service: "vitalanalysis",
        number: 2474,
    },
    PortDefinition {
        service: "vrt",
        number: 4991,
    },
    PortDefinition {
        service: "va-pacbase",
        number: 3676,
    },
    PortDefinition {
        service: "vts-rpc",
        number: 5780,
    },
    PortDefinition {
        service: "vista-4gl",
        number: 24249,
    },
    PortDefinition {
        service: "visitview",
        number: 1631,
    },
    PortDefinition {
        service: "vision_server",
        number: 6672,
    },
    PortDefinition {
        service: "vision_elmd",
        number: 6673,
    },
    PortDefinition {
        service: "visinet-gui",
        number: 3601,
    },
    PortDefinition {
        service: "vpm-udp",
        number: 5046,
    },
    PortDefinition {
        service: "vns-tp",
        number: 7802,
    },
    PortDefinition {
        service: "vt-ssl",
        number: 3509,
    },
    PortDefinition {
        service: "virtual-time",
        number: 1852,
    },
    PortDefinition {
        service: "virtualtape",
        number: 2386,
    },
    PortDefinition {
        service: "vp2p",
        number: 8473,
    },
    PortDefinition {
        service: "vxlan",
        number: 4789,
    },
    PortDefinition {
        service: "razor",
        number: 3555,
    },
    PortDefinition {
        service: "vipera-ssl",
        number: 12013,
    },
    PortDefinition {
        service: "vipera",
        number: 12012,
    },
    PortDefinition {
        service: "vipremoteagent",
        number: 3752,
    },
    PortDefinition {
        service: "vieo-fe",
        number: 3245,
    },
    PortDefinition {
        service: "vidigo",
        number: 3231,
    },
    PortDefinition {
        service: "vtp",
        number: 16666,
    },
    PortDefinition {
        service: "vfbp",
        number: 6678,
    },
    PortDefinition {
        service: "vestasdlp",
        number: 17184,
    },
    PortDefinition {
        service: "net2display",
        number: 9086,
    },
    PortDefinition {
        service: "vscp",
        number: 9598,
    },
    PortDefinition {
        service: "vcrp",
        number: 3073,
    },
    PortDefinition {
        service: "vrtl-vmf-sa",
        number: 2074,
    },
    PortDefinition {
        service: "vrtl-vmf-ds",
        number: 1956,
    },
    PortDefinition {
        service: "versa-tek",
        number: 2610,
    },
    PortDefinition {
        service: "versatalk",
        number: 3738,
    },
    PortDefinition {
        service: "veritas-tcp1",
        number: 2802,
    },
    PortDefinition {
        service: "nomdb",
        number: 13786,
    },
    PortDefinition {
        service: "veritas-vis2",
        number: 2994,
    },
    PortDefinition {
        service: "veritas-vis1",
        number: 2993,
    },
    PortDefinition {
        service: "vrtstrapserver",
        number: 1885,
    },
    PortDefinition {
        service: "vrts-tdd",
        number: 14149,
    },
    PortDefinition {
        service: "itap-ddtp",
        number: 10100,
    },
    PortDefinition {
        service: "visd",
        number: 9284,
    },
    PortDefinition {
        service: "vcscmd",
        number: 14150,
    },
    PortDefinition {
        service: "bctp-server",
        number: 10107,
    },
    PortDefinition {
        service: "vrts-auth-port",
        number: 4032,
    },
    PortDefinition {
        service: "vrts-at-port",
        number: 2821,
    },
    PortDefinition {
        service: "vx-auth-port",
        number: 3207,
    },
    PortDefinition {
        service: "vad",
        number: 14154,
    },
    PortDefinition {
        service: "vrmg-ip",
        number: 24323,
    },
    PortDefinition {
        service: "vergencecm",
        number: 2771,
    },
    PortDefinition {
        service: "vfmobile",
        number: 5646,
    },
    PortDefinition {
        service: "vcmp",
        number: 2426,
    },
    PortDefinition {
        service: "vdmmesh",
        number: 18668,
    },
    PortDefinition {
        service: "vcnet-link-v10",
        number: 2554,
    },
    PortDefinition {
        service: "vatata",
        number: 4188,
    },
    PortDefinition {
        service: "vaprtm",
        number: 3654,
    },
    PortDefinition {
        service: "v5ua",
        number: 5675,
    },
    PortDefinition {
        service: "v2g-secc",
        number: 15118,
    },
    PortDefinition {
        service: "suucp",
        number: 4031,
    },
    PortDefinition {
        service: "utsftp",
        number: 2529,
    },
    PortDefinition {
        service: "ua-secureagent",
        number: 19194,
    },
    PortDefinition {
        service: "ums",
        number: 2248,
    },
    PortDefinition {
        service: "edtools",
        number: 1142,
    },
    PortDefinition {
        service: "nnsp",
        number: 433,
    },
    PortDefinition {
        service: "urld-port",
        number: 3534,
    },
    PortDefinition {
        service: "ups-engine",
        number: 3664,
    },
    PortDefinition {
        service: "upgrade",
        number: 2537,
    },
    PortDefinition {
        service: "utime",
        number: 519,
    },
    PortDefinition {
        service: "unglue",
        number: 2655,
    },
    PortDefinition {
        service: "universe_suite",
        number: 4184,
    },
    PortDefinition {
        service: "utcd",
        number: 1506,
    },
    PortDefinition {
        service: "umm-port",
        number: 3098,
    },
    PortDefinition {
        service: "ubroker",
        number: 7887,
    },
    PortDefinition {
        service: "unisys-eportal",
        number: 37654,
    },
    PortDefinition {
        service: "unisql-java",
        number: 1979,
    },
    PortDefinition {
        service: "uniport",
        number: 9629,
    },
    PortDefinition {
        service: "unihub-server",
        number: 2357,
    },
    PortDefinition {
        service: "unify-adapter",
        number: 1889,
    },
    PortDefinition {
        service: "uohost",
        number: 3314,
    },
    PortDefinition {
        service: "uorb",
        number: 3313,
    },
    PortDefinition {
        service: "unify-debug",
        number: 4867,
    },
    PortDefinition {
        service: "unifyadmin",
        number: 2696,
    },
    PortDefinition {
        service: "unite",
        number: 3217,
    },
    PortDefinition {
        service: "ufmp",
        number: 6306,
    },
    PortDefinition {
        service: "unet",
        number: 1189,
    },
    PortDefinition {
        service: "undo-lm",
        number: 5281,
    },
    PortDefinition {
        service: "ub-dns-control",
        number: 8953,
    },
    PortDefinition {
        service: "ultrabac",
        number: 1910,
    },
    PortDefinition {
        service: "ucontrol",
        number: 13894,
    },
    PortDefinition {
        service: "ulistserv",
        number: 372,
    },
    PortDefinition {
        service: "ufastro-instr",
        number: 3720,
    },
    PortDefinition {
        service: "udt_os",
        number: 1382,
    },
    PortDefinition {
        service: "udrawgraph",
        number: 2542,
    },
    PortDefinition {
        service: "u-dbap",
        number: 3584,
    },
    PortDefinition {
        service: "ubxd",
        number: 4034,
    },
    PortDefinition {
        service: "uaac",
        number: 145,
    },
    PortDefinition {
        service: "tw-auth-key",
        number: 27999,
    },
    PortDefinition {
        service: "tvpm",
        number: 21800,
    },
    PortDefinition {
        service: "tve-announce",
        number: 2670,
    },
    PortDefinition {
        service: "tvdumtray-port",
        number: 3492,
    },
    PortDefinition {
        service: "tvnetworkvideo",
        number: 3791,
    },
    PortDefinition {
        service: "proactivate",
        number: 24678,
    },
    PortDefinition {
        service: "turbonote-2",
        number: 34249,
    },
    PortDefinition {
        service: "turbonote-1",
        number: 39681,
    },
    PortDefinition {
        service: "tunstall-pnc",
        number: 1846,
    },
    PortDefinition {
        service: "tunstall-lwp",
        number: 5197,
    },
    PortDefinition {
        service: "ttl-publisher",
        number: 5462,
    },
    PortDefinition {
        service: "ttlpriceproxy",
        number: 5463,
    },
    PortDefinition {
        service: "ttg-protocol",
        number: 2862,
    },
    PortDefinition {
        service: "ttc-etap-ns",
        number: 2977,
    },
    PortDefinition {
        service: "ttc-etap-ds",
        number: 2978,
    },
    PortDefinition {
        service: "ttcmremotectrl",
        number: 3468,
    },
    PortDefinition {
        service: "ttc-etap",
        number: 2675,
    },
    PortDefinition {
        service: "ttntspauto",
        number: 3474,
    },
    PortDefinition {
        service: "tsepisp",
        number: 4422,
    },
    PortDefinition {
        service: "tsaf",
        number: 12753,
    },
    PortDefinition {
        service: "netbackup",
        number: 13709,
    },
    PortDefinition {
        service: "twsdss",
        number: 3012,
    },
    PortDefinition {
        service: "trustestablish",
        number: 2573,
    },
    PortDefinition {
        service: "visicron-vs",
        number: 4307,
    },
    PortDefinition {
        service: "truckstar",
        number: 4725,
    },
    PortDefinition {
        service: "trnsprntproxy",
        number: 3346,
    },
    PortDefinition {
        service: "tnmpv2",
        number: 3686,
    },
    PortDefinition {
        service: "tripe",
        number: 4070,
    },
    PortDefinition {
        service: "trispen-sra",
        number: 9555,
    },
    PortDefinition {
        service: "trinity-dist",
        number: 4711,
    },
    PortDefinition {
        service: "trim-ice",
        number: 4323,
    },
    PortDefinition {
        service: "trim-event",
        number: 4322,
    },
    PortDefinition {
        service: "trisoap",
        number: 10200,
    },
    PortDefinition {
        service: "trident-data",
        number: 7727,
    },
    PortDefinition {
        service: "trendchip-dcp",
        number: 3608,
    },
    PortDefinition {
        service: "treehopper",
        number: 3959,
    },
    PortDefinition {
        service: "trc-netpoll",
        number: 2405,
    },
    PortDefinition {
        service: "trap-port-mom",
        number: 3858,
    },
    PortDefinition {
        service: "trap-port",
        number: 3857,
    },
    PortDefinition {
        service: "hid",
        number: 24322,
    },
    PortDefinition {
        service: "tipc",
        number: 6118,
    },
    PortDefinition {
        service: "tl-ipcproxy",
        number: 4176,
    },
    PortDefinition {
        service: "tarp",
        number: 6442,
    },
    PortDefinition {
        service: "twds",
        number: 8937,
    },
    PortDefinition {
        service: "trdp-pd",
        number: 17224,
    },
    PortDefinition {
        service: "trdp-md",
        number: 17225,
    },
    PortDefinition {
        service: "asa-gateways",
        number: 7234,
    },
    PortDefinition {
        service: "traceroute",
        number: 33434,
    },
    PortDefinition {
        service: "tpmd",
        number: 1906,
    },
    PortDefinition {
        service: "codemeter-cmwan",
        number: 22351,
    },
    PortDefinition {
        service: "touchnetplus",
        number: 2158,
    },
    PortDefinition {
        service: "toruxserver",
        number: 5153,
    },
    PortDefinition {
        service: "topflow-ssl",
        number: 3885,
    },
    PortDefinition {
        service: "tonidods",
        number: 24465,
    },
    PortDefinition {
        service: "tomato-springs",
        number: 3040,
    },
    PortDefinition {
        service: "tolfab",
        number: 20167,
    },
    PortDefinition {
        service: "toad-bi-appsrvr",
        number: 8066,
    },
    PortDefinition {
        service: "tn-tl-w1",
        number: 474,
    },
    PortDefinition {
        service: "tns-server",
        number: 3308,
    },
    PortDefinition {
        service: "tns-cml",
        number: 590,
    },
    PortDefinition {
        service: "tns-adv",
        number: 3309,
    },
    PortDefinition {
        service: "tnos-dp",
        number: 7902,
    },
    PortDefinition {
        service: "tnos-sp",
        number: 7901,
    },
    PortDefinition {
        service: "tnos-dps",
        number: 7903,
    },
    PortDefinition {
        service: "tn-timing",
        number: 2739,
    },
    PortDefinition {
        service: "tmophl7mts",
        number: 20046,
    },
    PortDefinition {
        service: "fac-restore",
        number: 5582,
    },
    PortDefinition {
        service: "tmo-icon-sync",
        number: 5583,
    },
    PortDefinition {
        service: "mipv6tls",
        number: 7872,
    },
    PortDefinition {
        service: "netbackup",
        number: 13716,
    },
    PortDefinition {
        service: "netbackup",
        number: 13717,
    },
    PortDefinition {
        service: "netbackup",
        number: 13705,
    },
    PortDefinition {
        service: "tl1-ssh",
        number: 6252,
    },
    PortDefinition {
        service: "tksocket",
        number: 2915,
    },
    PortDefinition {
        service: "tivoli-npm",
        number: 1965,
    },
    PortDefinition {
        service: "integral",
        number: 3459,
    },
    PortDefinition {
        service: "tip-app-server",
        number: 3160,
    },
    PortDefinition {
        service: "timestenbroker",
        number: 3754,
    },
    PortDefinition {
        service: "timelot",
        number: 3243,
    },
    PortDefinition {
        service: "tile-ml",
        number: 10261,
    },
    PortDefinition {
        service: "t2-drm",
        number: 7932,
    },
    PortDefinition {
        service: "t2-brm",
        number: 7933,
    },
    PortDefinition {
        service: "tiepie",
        number: 5450,
    },
    PortDefinition {
        service: "tibsd",
        number: 11971,
    },
    PortDefinition {
        service: "is99c",
        number: 379,
    },
    PortDefinition {
        service: "tidp",
        number: 7548,
    },
    PortDefinition {
        service: "tht-treasure",
        number: 1832,
    },
    PortDefinition {
        service: "tcpdataserver",
        number: 3805,
    },
    PortDefinition {
        service: "cadsisvr",
        number: 16789,
    },
    PortDefinition {
        service: "thingkit",
        number: 4423,
    },
    PortDefinition {
        service: "tnp-discover",
        number: 8320,
    },
    PortDefinition {
        service: "tnp",
        number: 8321,
    },
    PortDefinition {
        service: "theta-lm",
        number: 2296,
    },
    PortDefinition {
        service: "swx",
        number: 7359,
    },
    PortDefinition {
        service: "swx",
        number: 7358,
    },
    PortDefinition {
        service: "swx",
        number: 7357,
    },
    PortDefinition {
        service: "swx",
        number: 7356,
    },
    PortDefinition {
        service: "swx",
        number: 7355,
    },
    PortDefinition {
        service: "swx",
        number: 7354,
    },
    PortDefinition {
        service: "swx",
        number: 7353,
    },
    PortDefinition {
        service: "swx",
        number: 7352,
    },
    PortDefinition {
        service: "swx",
        number: 7351,
    },
    PortDefinition {
        service: "swx",
        number: 7350,
    },
    PortDefinition {
        service: "swx",
        number: 7349,
    },
    PortDefinition {
        service: "swx",
        number: 7348,
    },
    PortDefinition {
        service: "swx",
        number: 7347,
    },
    PortDefinition {
        service: "swx",
        number: 7346,
    },
    PortDefinition {
        service: "swx",
        number: 7344,
    },
    PortDefinition {
        service: "swx",
        number: 7343,
    },
    PortDefinition {
        service: "swx",
        number: 7342,
    },
    PortDefinition {
        service: "swx",
        number: 7341,
    },
    PortDefinition {
        service: "swx",
        number: 7340,
    },
    PortDefinition {
        service: "swx",
        number: 7339,
    },
    PortDefinition {
        service: "swx",
        number: 7338,
    },
    PortDefinition {
        service: "swx",
        number: 7337,
    },
    PortDefinition {
        service: "swx",
        number: 7336,
    },
    PortDefinition {
        service: "swx",
        number: 7335,
    },
    PortDefinition {
        service: "swx",
        number: 7334,
    },
    PortDefinition {
        service: "swx",
        number: 7333,
    },
    PortDefinition {
        service: "swx",
        number: 7332,
    },
    PortDefinition {
        service: "swx",
        number: 7331,
    },
    PortDefinition {
        service: "swx",
        number: 7330,
    },
    PortDefinition {
        service: "swx",
        number: 7329,
    },
    PortDefinition {
        service: "swx",
        number: 7328,
    },
    PortDefinition {
        service: "swx",
        number: 7327,
    },
    PortDefinition {
        service: "swx",
        number: 7324,
    },
    PortDefinition {
        service: "swx",
        number: 7323,
    },
    PortDefinition {
        service: "swx",
        number: 7322,
    },
    PortDefinition {
        service: "swx",
        number: 7321,
    },
    PortDefinition {
        service: "swx",
        number: 7319,
    },
    PortDefinition {
        service: "swx",
        number: 7318,
    },
    PortDefinition {
        service: "swx",
        number: 7317,
    },
    PortDefinition {
        service: "swx",
        number: 7316,
    },
    PortDefinition {
        service: "swx",
        number: 7315,
    },
    PortDefinition {
        service: "swx",
        number: 7314,
    },
    PortDefinition {
        service: "swx",
        number: 7313,
    },
    PortDefinition {
        service: "swx",
        number: 7312,
    },
    PortDefinition {
        service: "swx",
        number: 7311,
    },
    PortDefinition {
        service: "swx",
        number: 7310,
    },
    PortDefinition {
        service: "swx",
        number: 7309,
    },
    PortDefinition {
        service: "swx",
        number: 7308,
    },
    PortDefinition {
        service: "swx",
        number: 7307,
    },
    PortDefinition {
        service: "swx",
        number: 7306,
    },
    PortDefinition {
        service: "swx",
        number: 7305,
    },
    PortDefinition {
        service: "swx",
        number: 7304,
    },
    PortDefinition {
        service: "swx",
        number: 7303,
    },
    PortDefinition {
        service: "swx",
        number: 7302,
    },
    PortDefinition {
        service: "swx",
        number: 7301,
    },
    PortDefinition {
        service: "puppet",
        number: 8140,
    },
    PortDefinition {
        service: "ampl-tableproxy",
        number: 5196,
    },
    PortDefinition {
        service: "ampl-lic",
        number: 5195,
    },
    PortDefinition {
        service: "damewaremobgtwy",
        number: 6130,
    },
    PortDefinition {
        service: "apsolab-rpc",
        number: 5474,
    },
    PortDefinition {
        service: "apsolab-cols",
        number: 5471,
    },
    PortDefinition {
        service: "apsolab-tag",
        number: 5472,
    },
    PortDefinition {
        service: "apsolab-col",
        number: 5470,
    },
    PortDefinition {
        service: "tgcconnect",
        number: 4146,
    },
    PortDefinition {
        service: "tftps",
        number: 3713,
    },
    PortDefinition {
        service: "texai",
        number: 5048,
    },
    PortDefinition {
        service: "tetrinet",
        number: 31457,
    },
    PortDefinition {
        service: "tesla-sys-msg",
        number: 7631,
    },
    PortDefinition {
        service: "teredo",
        number: 3544,
    },
    PortDefinition {
        service: "tentacle",
        number: 41121,
    },
    PortDefinition {
        service: "tempest-port",
        number: 11600,
    },
    PortDefinition {
        service: "telnetcpcd",
        number: 3696,
    },
    PortDefinition {
        service: "tellumat-nms",
        number: 3549,
    },
    PortDefinition {
        service: "telesis-licman",
        number: 1380,
    },
    PortDefinition {
        service: "brf-gw",
        number: 22951,
    },
    PortDefinition {
        service: "aws-brf",
        number: 22800,
    },
    PortDefinition {
        service: "mc3ss",
        number: 3521,
    },
    PortDefinition {
        service: "teleniumdaemon",
        number: 2060,
    },
    PortDefinition {
        service: "miami-bcast",
        number: 6083,
    },
    PortDefinition {
        service: "tec5-sdctp",
        number: 9668,
    },
    PortDefinition {
        service: "taserver",
        number: 3552,
    },
    PortDefinition {
        service: "tdp-suite",
        number: 1814,
    },
    PortDefinition {
        service: "tcoaddressbook",
        number: 1977,
    },
    PortDefinition {
        service: "tclprodebugger",
        number: 2576,
    },
    PortDefinition {
        service: "tcim-control",
        number: 2729,
    },
    PortDefinition {
        service: "tcc-http",
        number: 24680,
    },
    PortDefinition {
        service: "netbackup",
        number: 13710,
    },
    PortDefinition {
        service: "netbackup",
        number: 13712,
    },
    PortDefinition {
        service: "tasp-net",
        number: 25900,
    },
    PortDefinition {
        service: "taskmaster2000",
        number: 2403,
    },
    PortDefinition {
        service: "taskmaster2000",
        number: 2402,
    },
    PortDefinition {
        service: "taskman-port",
        number: 2470,
    },
    PortDefinition {
        service: "targus-getdata3",
        number: 5203,
    },
    PortDefinition {
        service: "ttat3lb",
        number: 3579,
    },
    PortDefinition {
        service: "tappi-boxnet",
        number: 2306,
    },
    PortDefinition {
        service: "dwf",
        number: 1450,
    },
    PortDefinition {
        service: "talon-webserver",
        number: 7015,
    },
    PortDefinition {
        service: "talon-engine",
        number: 7012,
    },
    PortDefinition {
        service: "talon-disc",
        number: 7011,
    },
    PortDefinition {
        service: "talikaserver",
        number: 22763,
    },
    PortDefinition {
        service: "talarian-mqs",
        number: 2493,
    },
    PortDefinition {
        service: "talarian-mcast5",
        number: 4019,
    },
    PortDefinition {
        service: "talarian-mcast4",
        number: 4018,
    },
    PortDefinition {
        service: "talarian-mcast3",
        number: 4017,
    },
    PortDefinition {
        service: "talarian-mcast1",
        number: 4015,
    },
    PortDefinition {
        service: "trp",
        number: 2156,
    },
    PortDefinition {
        service: "tacticalauth",
        number: 2392,
    },
    PortDefinition {
        service: "t1-e1-over-ip",
        number: 3175,
    },
    PortDefinition {
        service: "t1distproc60",
        number: 32249,
    },
    PortDefinition {
        service: "t128-gateway",
        number: 1627,
    },
    PortDefinition {
        service: "swdtp",
        number: 10104,
    },
    PortDefinition {
        service: "systemics-sox",
        number: 5406,
    },
    PortDefinition {
        service: "system-monitor",
        number: 2609,
    },
    PortDefinition {
        service: "sysrqd",
        number: 4094,
    },
    PortDefinition {
        service: "sysorb",
        number: 3241,
    },
    PortDefinition {
        service: "syslog-tls",
        number: 6514,
    },
    PortDefinition {
        service: "syserverremote",
        number: 6418,
    },
    PortDefinition {
        service: "sysscanner",
        number: 3251,
    },
    PortDefinition {
        service: "synel-data",
        number: 3734,
    },
    PortDefinition {
        service: "dbsyncarbiter",
        number: 4953,
    },
    PortDefinition {
        service: "syncserverssl",
        number: 2679,
    },
    PortDefinition {
        service: "synapsis-edge",
        number: 5008,
    },
    PortDefinition {
        service: "synapse",
        number: 2880,
    },
    PortDefinition {
        service: "synapse-nhttps",
        number: 8243,
    },
    PortDefinition {
        service: "synapse-nhttp",
        number: 8280,
    },
    PortDefinition {
        service: "scscp",
        number: 26133,
    },
    PortDefinition {
        service: "d-fence",
        number: 8555,
    },
    PortDefinition {
        service: "symantec-sfdb",
        number: 5629,
    },
    PortDefinition {
        service: "symantec-sim",
        number: 3547,
    },
    PortDefinition {
        service: "ics",
        number: 5639,
    },
    PortDefinition {
        service: "flcrs",
        number: 5638,
    },
    PortDefinition {
        service: "cssc",
        number: 5637,
    },
    PortDefinition {
        service: "autobuild",
        number: 5115,
    },
    PortDefinition {
        service: "sychrond",
        number: 3723,
    },
    PortDefinition {
        service: "sybasesrvmon",
        number: 4950,
    },
    PortDefinition {
        service: "syam-smc",
        number: 3895,
    },
    PortDefinition {
        service: "syam-agent",
        number: 3894,
    },
    PortDefinition {
        service: "swr-port",
        number: 3491,
    },
    PortDefinition {
        service: "ssrip",
        number: 3318,
    },
    PortDefinition {
        service: "svdrp",
        number: 6419,
    },
    PortDefinition {
        service: "smpppd",
        number: 3185,
    },
    PortDefinition {
        service: "sur-meas",
        number: 243,
    },
    PortDefinition {
        service: "surveyinst",
        number: 3212,
    },
    PortDefinition {
        service: "laes-bf",
        number: 9536,
    },
    PortDefinition {
        service: "discovery-port",
        number: 1925,
    },
    PortDefinition {
        service: "snss",
        number: 11171,
    },
    PortDefinition {
        service: "svcloud",
        number: 8404,
    },
    PortDefinition {
        service: "svbackup",
        number: 8405,
    },
    PortDefinition {
        service: "SunVTS-RMI",
        number: 6483,
    },
    PortDefinition {
        service: "sunscalar-svc",
        number: 1860,
    },
    PortDefinition {
        service: "sunscalar-dns",
        number: 1870,
    },
    PortDefinition {
        service: "sunclustergeo",
        number: 2084,
    },
    PortDefinition {
        service: "sunwebadmins",
        number: 8989,
    },
    PortDefinition {
        service: "smc-admin",
        number: 6787,
    },
    PortDefinition {
        service: "dzoglserver",
        number: 3867,
    },
    PortDefinition {
        service: "dzdaemon",
        number: 3866,
    },
    PortDefinition {
        service: "sun-mc-grp",
        number: 5306,
    },
    PortDefinition {
        service: "sunlps-http",
        number: 3816,
    },
    PortDefinition {
        service: "sun-lm",
        number: 7588,
    },
    PortDefinition {
        service: "smc-jmx",
        number: 6786,
    },
    PortDefinition {
        service: "suncacao-websvc",
        number: 11165,
    },
    PortDefinition {
        service: "suncacao-snmp",
        number: 11161,
    },
    PortDefinition {
        service: "suncacao-rmi",
        number: 11163,
    },
    PortDefinition {
        service: "suncacao-jmxmp",
        number: 11162,
    },
    PortDefinition {
        service: "suncacao-csa",
        number: 11164,
    },
    PortDefinition {
        service: "sun-as-iiops",
        number: 3708,
    },
    PortDefinition {
        service: "sun-as-nodeagt",
        number: 4850,
    },
    PortDefinition {
        service: "sun-user-https",
        number: 7677,
    },
    PortDefinition {
        service: "subseven",
        number: 16959,
    },
    PortDefinition {
        service: "subntbcst_tftp",
        number: 247,
    },
    PortDefinition {
        service: "stuns",
        number: 5349,
    },
    PortDefinition {
        service: "stun",
        number: 3478,
    },
    PortDefinition {
        service: "stryker-com",
        number: 3854,
    },
    PortDefinition {
        service: "stresstester",
        number: 5397,
    },
    PortDefinition {
        service: "daqstream",
        number: 7411,
    },
    PortDefinition {
        service: "streamcomm-ds",
        number: 9612,
    },
    PortDefinition {
        service: "t5-straton",
        number: 11173,
    },
    PortDefinition {
        service: "storview",
        number: 9293,
    },
    PortDefinition {
        service: "strexec-s",
        number: 5027,
    },
    PortDefinition {
        service: "strexec-d",
        number: 5026,
    },
    PortDefinition {
        service: "storageos",
        number: 5705,
    },
    PortDefinition {
        service: "uec",
        number: 8778,
    },
    PortDefinition {
        service: "stx",
        number: 527,
    },
    PortDefinition {
        service: "sti-envision",
        number: 1312,
    },
    PortDefinition {
        service: "ssports-bcast",
        number: 8808,
    },
    PortDefinition {
        service: "statsci1-lm",
        number: 6144,
    },
    PortDefinition {
        service: "sttunnel",
        number: 7471,
    },
    PortDefinition {
        service: "ssp",
        number: 3249,
    },
    PortDefinition {
        service: "stat-scanner",
        number: 4157,
    },
    PortDefinition {
        service: "stat-results",
        number: 4156,
    },
    PortDefinition {
        service: "start-network",
        number: 3615,
    },
    PortDefinition {
        service: "dali-port",
        number: 5777,
    },
    PortDefinition {
        service: "stdptc",
        number: 2154,
    },
    PortDefinition {
        service: "ssr-servermgr",
        number: 45966,
    },
    PortDefinition {
        service: "ssh-mgmt",
        number: 17235,
    },
    PortDefinition {
        service: "srvc_registry",
        number: 3018,
    },
    PortDefinition {
        service: "sruth",
        number: 38800,
    },
    PortDefinition {
        service: "srp-feedback",
        number: 2737,
    },
    PortDefinition {
        service: "sqlsrv",
        number: 156,
    },
    PortDefinition {
        service: "spugna",
        number: 3807,
    },
    PortDefinition {
        service: "spss-lm",
        number: 1759,
    },
    PortDefinition {
        service: "sps-tunnel",
        number: 2876,
    },
    PortDefinition {
        service: "sossd-collect",
        number: 7981,
    },
    PortDefinition {
        service: "splitlock",
        number: 3606,
    },
    PortDefinition {
        service: "splitlock-gw",
        number: 3647,
    },
    PortDefinition {
        service: "spiral-admin",
        number: 3438,
    },
    PortDefinition {
        service: "spike",
        number: 4683,
    },
    PortDefinition {
        service: "sphinxql",
        number: 9306,
    },
    PortDefinition {
        service: "sphinxapi",
        number: 9312,
    },
    PortDefinition {
        service: "spg",
        number: 7016,
    },
    PortDefinition {
        service: "speedtrace",
        number: 33334,
    },
    PortDefinition {
        service: "svnet",
        number: 3413,
    },
    PortDefinition {
        service: "spectardb",
        number: 3835,
    },
    PortDefinition {
        service: "spectardata",
        number: 3834,
    },
    PortDefinition {
        service: "spearway",
        number: 2440,
    },
    PortDefinition {
        service: "spdy",
        number: 6121,
    },
    PortDefinition {
        service: "spamtrap",
        number: 2568,
    },
    PortDefinition {
        service: "soundsvirtual",
        number: 17185,
    },
    PortDefinition {
        service: "sossd-agent",
        number: 7982,
    },
    PortDefinition {
        service: "sonus-logging",
        number: 2290,
    },
    PortDefinition {
        service: "sonuscallsig",
        number: 2569,
    },
    PortDefinition {
        service: "sonardata",
        number: 2863,
    },
    PortDefinition {
        service: "solid-e-engine",
        number: 1964,
    },
    PortDefinition {
        service: "solera-lpn",
        number: 4738,
    },
    PortDefinition {
        service: "solera-epmap",
        number: 2132,
    },
    PortDefinition {
        service: "sw-orion",
        number: 17777,
    },
    PortDefinition {
        service: "solaris-audit",
        number: 16162,
    },
    PortDefinition {
        service: "sum",
        number: 6551,
    },
    PortDefinition {
        service: "sftdst-port",
        number: 3230,
    },
    PortDefinition {
        service: "swx-gate",
        number: 4538,
    },
    PortDefinition {
        service: "softrack-meter",
        number: 3884,
    },
    PortDefinition {
        service: "swtp-port2",
        number: 9282,
    },
    PortDefinition {
        service: "swtp-port1",
        number: 9281,
    },
    PortDefinition {
        service: "socp-c",
        number: 4882,
    },
    PortDefinition {
        service: "social-alarm",
        number: 5146,
    },
    PortDefinition {
        service: "sntp-heartbeat",
        number: 580,
    },
    PortDefinition {
        service: "sns-quote",
        number: 1967,
    },
    PortDefinition {
        service: "sns-query",
        number: 2659,
    },
    PortDefinition {
        service: "sns-protocol",
        number: 2409,
    },
    PortDefinition {
        service: "sns-gateway",
        number: 5416,
    },
    PortDefinition {
        service: "sns-dispatcher",
        number: 2657,
    },
    PortDefinition {
        service: "sns-channels",
        number: 3380,
    },
    PortDefinition {
        service: "sns-agent",
        number: 5417,
    },
    PortDefinition {
        service: "sns-admin",
        number: 2658,
    },
    PortDefinition {
        service: "snmptls-trap",
        number: 10162,
    },
    PortDefinition {
        service: "snmptls",
        number: 10161,
    },
    PortDefinition {
        service: "snmpssh",
        number: 5161,
    },
    PortDefinition {
        service: "snmpssh-trap",
        number: 5162,
    },
    PortDefinition {
        service: "snip-slave",
        number: 33656,
    },
    PortDefinition {
        service: "sncp",
        number: 7560,
    },
    PortDefinition {
        service: "snapd",
        number: 2599,
    },
    PortDefinition {
        service: "sms-remctrl",
        number: 2704,
    },
    PortDefinition {
        service: "sms-chat",
        number: 2703,
    },
    PortDefinition {
        service: "d-cinema-csp",
        number: 4170,
    },
    PortDefinition {
        service: "smip",
        number: 7734,
    },
    PortDefinition {
        service: "stvp",
        number: 3158,
    },
    PortDefinition {
        service: "beacon-port-2",
        number: 4426,
    },
    PortDefinition {
        service: "smartcard-port",
        number: 3516,
    },
    PortDefinition {
        service: "smart-install",
        number: 4786,
    },
    PortDefinition {
        service: "smart-diagnose",
        number: 2721,
    },
    PortDefinition {
        service: "smart-lm",
        number: 1608,
    },
    PortDefinition {
        service: "smar-se-port2",
        number: 4988,
    },
    PortDefinition {
        service: "sma-spw",
        number: 9522,
    },
    PortDefinition {
        service: "slscc",
        number: 4408,
    },
    PortDefinition {
        service: "slp-notify",
        number: 1847,
    },
    PortDefinition {
        service: "slmap",
        number: 36423,
    },
    PortDefinition {
        service: "slc-systemlog",
        number: 2826,
    },
    PortDefinition {
        service: "slc-ctrlrloops",
        number: 2827,
    },
    PortDefinition {
        service: "skynetflow",
        number: 8111,
    },
    PortDefinition {
        service: "sky-transport",
        number: 3556,
    },
    PortDefinition {
        service: "skip-cert-send",
        number: 6456,
    },
    PortDefinition {
        service: "skip-cert-recv",
        number: 6455,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Check if the first 10 ports are correct
    #[test]
    fn get_common_ports_10() {
        let expected = &[
            Port {
                service: "http".to_string(),
                number: 80,
                is_open: None,
            },
            Port {
                service: "telnet".to_string(),
                number: 23,
                is_open: None,
            },
            Port {
                service: "https".to_string(),
                number: 443,
                is_open: None,
            },
            Port {
                service: "ftp".to_string(),
                number: 21,
                is_open: None,
            },
            Port {
                service: "ssh".to_string(),
                number: 22,
                is_open: None,
            },
            Port {
                service: "smtp".to_string(),
                number: 25,
                is_open: None,
            },
            Port {
                service: "ms-wbt-server".to_string(),
                number: 3389,
                is_open: None,
            },
            Port {
                service: "pop3".to_string(),
                number: 110,
                is_open: None,
            },
            Port {
                service: "microsoft-ds".to_string(),
                number: 445,
                is_open: None,
            },
            Port {
                service: "netbios-ssn".to_string(),
                number: 139,
                is_open: None,
            },
        ];

        let result = get_common_ports(10);

        assert!(result.len() == 10);
        for i in 0..10 {
            assert_eq!(result[i], expected[i]);
        }
    }

    /// Check that `get_common_ports(0)` returns an empty vector
    #[test]
    fn get_common_ports_0() {
        let result = get_common_ports(0);

        assert!(result.is_empty());
    }

    /// Check that `n` is capped at 5000
    #[test]
    fn get_common_ports_6000() {
        let result = get_common_ports(6000);

        assert!(result.len() == 5000);
    }
}
