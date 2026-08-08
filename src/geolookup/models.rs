use serde::Serialize;

/// Geographic data resolved for a proxy IP address.
///
/// Every field is optional: the MaxMind database does not cover all addresses,
/// and a lookup may legitimately produce a partial record.
#[derive(Debug, Default, Clone, Serialize)]
pub struct GeoData {
    /// Two-letter ISO 3166 country code (e.g. `ID`).
    pub iso_code: Option<String>,
    /// English country name.
    pub name: Option<String>,
    /// ISO code of the first-level region (e.g. US state).
    pub region_iso_code: Option<String>,
    /// English name of the region.
    pub region_name: Option<String>,
    /// English name of the city.
    pub city_name: Option<String>,
}
