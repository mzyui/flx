use serde::Serialize;

/// Contains geographical data related to a proxy.
#[derive(Debug, Default, Clone, Serialize)]
pub struct GeoData {
    /// ISO country code.
    pub iso_code: Option<String>,
    /// Country name.
    pub name: Option<String>,
    /// ISO code for the region.
    pub region_iso_code: Option<String>,
    /// Name of the region.
    pub region_name: Option<String>,
    /// Name of the city.
    pub city_name: Option<String>,
}
