use serde::Serialize;

/// Geographic data resolved for a proxy IP address.
///
/// Every field is optional: the MaxMind database does not cover all addresses,
/// and a lookup may legitimately produce a partial record. Fields are stored as
/// `Box<str>` (16 bytes, no spare capacity) instead of `String` (24 bytes plus
/// capacity) since they are never mutated once resolved.
#[derive(Debug, Default, Clone, Serialize)]
pub struct GeoData {
    /// Two-letter ISO 3166 country code (e.g. `ID`).
    ///
    /// Falls back to the two-letter continent code (e.g. `EU`, `AS`) when the
    /// database reports no country for the address (see `extract_country_data`).
    pub iso_code: Option<Box<str>>,
    /// English country name.
    pub name: Option<Box<str>>,
    /// ISO code of the first-level region (e.g. US state).
    pub region_iso_code: Option<Box<str>>,
    /// English name of the region.
    pub region_name: Option<Box<str>>,
    /// English name of the city.
    pub city_name: Option<Box<str>>,
}
