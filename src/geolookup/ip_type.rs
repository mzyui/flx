use serde::Serialize;

/// IP address class distinguishing residential from hosted networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IpType {
    Residential,
    Datacenter,
    Mobile,
    #[default]
    Unknown,
}

// Curated seed of well-known cloud and hosting ASNs; maintenance required as
// provider assignments shift over time.
const HOSTING_ASNS: &[u32] = &[
    174, 2906, 8075, 8560, 12222, 12876, 13335, 13415, 14061, 14618, 15169, 16265, 16276, 16509,
    16625, 19318, 19551, 20454, 20473, 20940, 21859, 24940, 26496, 29802, 31898, 33070, 35540,
    36351, 40676, 42708, 46664, 47583, 49981, 51167, 54113, 54290, 61157, 63949, 197540, 199524,
    213230, 396982,
];

const HOSTING_KEYWORDS: &[&str] = &[
    "amazon",
    "aws",
    "azure",
    "microsoft",
    "google",
    "oracle",
    "digitalocean",
    "hetzner",
    "ovh",
    "linode",
    "akamai",
    "cloudflare",
    "fastly",
    "vultr",
    "choopa",
    "leaseweb",
    "contabo",
    "ionos",
    "hostinger",
    "hostgator",
    "bluehost",
    "dreamhost",
    "scaleway",
    "rackspace",
    "softlayer",
    "equinix",
    "cogent",
    "zenlayer",
    "gcore",
    "psychz",
    "interserver",
    "hivelocity",
    "kamatera",
    "phoenixnap",
    "netcup",
    "incapsula",
    "hosting",
    "colo",
    "datacenter",
    "data center",
    "dedicated server",
    "vps",
    "cloud",
];

const MOBILE_KEYWORDS: &[&str] = &[
    "mobile",
    "wireless",
    "cellular",
    "gsm",
    "lte",
    "telekom",
    "vodafone",
    "t-mobile",
    "verizon",
    "at&t mobility",
    "movistar",
    "claro",
    "oranj",
    "etisalat",
    "airtel",
    "mtn",
    "singtel",
    "indosat",
    "telkomsel",
    "smartfren",
    "xl axiata",
    "optus",
    "telstra",
    "docomo",
    "softbank",
    "sk telecom",
];

fn has_keyword(name: &str, keywords: &[&str]) -> bool {
    let name_bytes = name.as_bytes();
    keywords.iter().any(|keyword| {
        let keyword_bytes = keyword.as_bytes();
        // Case-insensitive substring scan without allocating a lowercase copy
        // on every classification.
        keyword_bytes.is_empty()
            || name_bytes
                .windows(keyword_bytes.len())
                .any(|window| window.eq_ignore_ascii_case(keyword_bytes))
    })
}

fn has_hosting_keyword(name: &str) -> bool {
    has_keyword(name, HOSTING_KEYWORDS)
}

fn has_mobile_keyword(name: &str) -> bool {
    has_keyword(name, MOBILE_KEYWORDS)
}

impl IpType {
    /// Classifies a proxy IP from its ASN and carrier metadata.
    pub fn classify(
        asn: Option<u32>,
        aso: Option<&str>,
        isp: Option<&str>,
        organization: Option<&str>,
    ) -> Self {
        let org = aso.or(isp).or(organization);
        if org.is_some_and(has_mobile_keyword) {
            return Self::Mobile;
        }
        if asn.is_some_and(|asn| HOSTING_ASNS.binary_search(&asn).is_ok())
            || org.is_some_and(has_hosting_keyword)
        {
            return Self::Datacenter;
        }
        if asn.is_some() || org.is_some() {
            return Self::Residential;
        }
        Self::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::IpType;

    #[test]
    fn mobile_carrier_aso_is_mobile() {
        assert_eq!(
            IpType::classify(Some(1234), Some("Telkomsel"), None, None),
            IpType::Mobile
        );
    }

    #[test]
    fn known_hosting_asn_is_datacenter() {
        assert_eq!(
            IpType::classify(Some(14061), None, None, None),
            IpType::Datacenter
        );
    }

    #[test]
    fn unknown_hosting_asn_is_datacenter_when_keyworded() {
        assert_eq!(
            IpType::classify(Some(999999), Some("Hetzner Cloud"), None, None),
            IpType::Datacenter
        );
    }

    #[test]
    fn residential_isp_with_asn_stays_residential() {
        assert_eq!(
            IpType::classify(
                Some(56046),
                Some("PT Telkom Indonesia"),
                Some("Telkom"),
                None
            ),
            IpType::Residential
        );
    }

    #[test]
    fn residential_when_only_isp_idents_are_present() {
        assert_eq!(
            IpType::classify(None, None, Some("Comcast"), None),
            IpType::Residential
        );
    }

    #[test]
    fn keyword_match_is_case_insensitive_without_allocation() {
        use super::{has_hosting_keyword, has_mobile_keyword, has_keyword, MOBILE_KEYWORDS};
        // Uppercase / mixed-case occurrences must match like the old lowercase
        // scan did, and an absent keyword must not.
        assert!(has_mobile_keyword("PT Telkomsel Indonesia"));
        assert!(has_mobile_keyword("telkomsel"));
        assert!(has_keyword("Azteca DEploy", MOBILE_KEYWORDS) == false);
        assert!(has_hosting_keyword("AMAZON AWS"));
    }

    #[test]
    fn empty_identifiers_yield_unknown() {
        assert_eq!(IpType::classify(None, None, None, None), IpType::Unknown);
    }

    #[test]
    fn serializes_to_lowercase() {
        for (ip_type, expected) in [
            (IpType::Residential, "\"residential\""),
            (IpType::Datacenter, "\"datacenter\""),
            (IpType::Mobile, "\"mobile\""),
            (IpType::Unknown, "\"unknown\""),
        ] {
            assert_eq!(serde_json::to_string(&ip_type).unwrap(), expected);
        }
    }

    #[test]
    fn binary_search_requires_sorted_asns() {
        assert!(super::HOSTING_ASNS.windows(2).all(|w| w[0] <= w[1]));
    }
}
