use serde::Serialize;

use super::ip_type::IpType;

#[derive(Debug, Default, Clone, Serialize)]
pub struct GeoData {
    pub iso_code: Option<Box<str>>,
    pub name: Option<Box<str>>,
    pub region_iso_code: Option<Box<str>>,
    pub region_name: Option<Box<str>>,
    pub city_name: Option<Box<str>>,
    pub ip_type: IpType,
}
