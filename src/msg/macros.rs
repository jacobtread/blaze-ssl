#[macro_export]
macro_rules! ssl_enum {
    (
        $(#[$comment:meta])*
        ($ty:ty) enum $name:ident {
            $(
                $enum_key:ident = $enum_value:expr
            ),* $(,)?
        }
    ) => {
        $(#[$comment])*
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        pub enum $name {
            $(
                $enum_key
            ),*,
            Unknown($ty)
        }

        impl $name {
            pub fn value(&self) -> $ty {
                match self {
                    $($name::$enum_key => $enum_value),*,
                    $name::Unknown(value) => value.clone()
                }
            }
        }

        impl From<$ty> for $name {
            fn from(value: $ty) -> Self {
                match value {
                    $($enum_value => $name::$enum_key),*,
                    value => $name::Unknown(value)
                }
            }
        }

        impl $crate::msg::codec::Codec for $name {
            fn encode(&self, output: &mut Vec<u8>) {
                self.value().encode(output);
            }

            fn decode(input: &mut $crate::msg::codec::Reader) -> Option<Self> {
                <$ty>::decode(input).map($name::from)
            }
        }
    };
}