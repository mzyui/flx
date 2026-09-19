//! GeoIP record types attached to validated proxies.
//!
//! [`GeoData`] is the per-proxy record; see [`GeoLookup`](crate::GeoLookup)
//! for database-backed resolution.

use serde::{
    ser::{SerializeMap, SerializeStruct},
    Serialize,
};

use super::ip_type::IpType;

/// Geolocation record attached to a [`Proxy`](crate::Proxy).
///
/// All fields are `None`/`Unknown` when lookup is disabled or the address
/// is unknown; see [`GeoData::is_empty`].
///
/// # Examples
///
/// ```
/// use flx::GeoData;
///
/// assert!(GeoData::default().is_empty());
/// ```
#[derive(Debug, Default, Clone)]
pub struct GeoData {
    /// ISO 3166-1 alpha-2 country code (e.g. `ID`).
    pub iso_code: Option<Box<str>>,
    /// Country name.
    pub name: Option<Box<str>>,
    /// Region ISO code.
    pub region_iso_code: Option<Box<str>>,
    /// Region name.
    pub region_name: Option<Box<str>>,
    /// City name.
    pub city_name: Option<Box<str>>,
    /// Autonomous system number.
    pub asn: Option<u32>,
    /// Autonomous system organization.
    pub aso: Option<Box<str>>,
    /// Address classification; see [`IpType`].
    pub ip_type: IpType,
    /// Continent code (e.g. `AS`).
    pub continent_code: Option<Box<str>>,
    /// Continent name.
    pub continent_name: Option<Box<str>>,
    /// Latitude in degrees.
    pub latitude: Option<f64>,
    /// Longitude in degrees.
    pub longitude: Option<f64>,
    /// IANA timezone (e.g. `Asia/Jakarta`).
    pub timezone: Option<Box<str>>,
    /// Postal code.
    pub zip: Option<Box<str>>,
}

impl GeoData {
    /// Whether the record carries no lookup data at all.
    ///
    /// Used to render `geo` as `{}` when geolocation is disabled (or the
    /// address is unknown) instead of an object full of nulls.
    pub fn is_empty(&self) -> bool {
        self.iso_code.is_none()
            && self.name.is_none()
            && self.region_iso_code.is_none()
            && self.region_name.is_none()
            && self.city_name.is_none()
            && self.asn.is_none()
            && self.aso.is_none()
            && self.ip_type == IpType::Unknown
            && self.continent_code.is_none()
            && self.continent_name.is_none()
            && self.latitude.is_none()
            && self.longitude.is_none()
            && self.timezone.is_none()
            && self.zip.is_none()
    }
}

impl Serialize for GeoData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.is_empty() {
            return serializer.serialize_map(None)?.end();
        }
        let mut state = serializer.serialize_struct("GeoData", 14)?;
        state.serialize_field("iso_code", &self.iso_code)?;
        state.serialize_field("name", &self.name)?;
        state.serialize_field("region_iso_code", &self.region_iso_code)?;
        state.serialize_field("region_name", &self.region_name)?;
        state.serialize_field("city_name", &self.city_name)?;
        state.serialize_field("asn", &self.asn)?;
        state.serialize_field("aso", &self.aso)?;
        state.serialize_field("ip_type", &self.ip_type)?;
        state.serialize_field("continent_code", &self.continent_code)?;
        state.serialize_field("continent_name", &self.continent_name)?;
        state.serialize_field("latitude", &self.latitude)?;
        state.serialize_field("longitude", &self.longitude)?;
        state.serialize_field("timezone", &self.timezone)?;
        state.serialize_field("zip", &self.zip)?;
        state.end()
    }
}

#[cfg(test)]
mod tests {
    use super::GeoData;
    use crate::geolookup::IpType;

    #[test]
    fn default_record_serializes_as_empty_object() {
        let value = serde_json::to_value(GeoData::default()).unwrap();
        assert_eq!(value, serde_json::json!({}));
        assert!(GeoData::default().is_empty());
    }

    #[test]
    fn populated_record_keeps_all_keys() {
        let data = GeoData {
            iso_code: Some("ID".into()),
            name: Some("Indonesia".into()),
            city_name: Some("Surakarta".into()),
            continent_code: Some("AS".into()),
            continent_name: Some("Asia".into()),
            latitude: Some(-7.5819),
            longitude: Some(110.8262),
            timezone: Some("Asia/Jakarta".into()),
            zip: Some("57156".into()),
            ..GeoData::default()
        };
        assert!(!data.is_empty());
        let value = serde_json::to_value(&data).unwrap();
        assert_eq!(value["iso_code"], "ID");
        assert_eq!(value["continent_code"], "AS");
        assert_eq!(value["continent_name"], "Asia");
        assert_eq!(value["latitude"], -7.5819);
        assert_eq!(value["longitude"], 110.8262);
        assert_eq!(value["timezone"], "Asia/Jakarta");
        assert_eq!(value["zip"], "57156");
    }

    #[test]
    fn ip_type_alone_marks_record_non_empty() {
        let data = GeoData {
            ip_type: IpType::Mobile,
            ..GeoData::default()
        };
        assert!(!data.is_empty());
        let value = serde_json::to_value(&data).unwrap();
        assert!(value.is_object());
        assert_eq!(value["ip_type"], "mobile");
    }
}
