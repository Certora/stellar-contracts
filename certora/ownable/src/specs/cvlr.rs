pub trait CvlrProp {
    fn assume_pre(&self);
    fn check_post(&self, old: &Self);

    /// Relational assumptions between current and old
    fn assume_post(&self, _old: &Self) {}
}

#[macro_export]
macro_rules! impl_cvlr_rule_for_base {
    ($prop: ident, $name: ident, $base: ident) => {
        /// Rule for $name
        #[cvlr_soroban_derive::rule]
        pub fn $name(e: Env) {
            $base::<$prop>(&e);
        }
    };
}

#[macro_export]
macro_rules! impl_cvlr_rule_for_bases {
    ($prop: ident $(, $rule:ident => $base:ident)+ $(,)? ) => {
        $($crate::impl_cvlr_rule_for_base!($prop, $rule, $base);)*
    }
}

#[macro_export]
macro_rules! impl_cvlr_log {
    ($prop:path $(, $field:ident)* $(,)?) => {
        impl cvlr::log::CvlrLog for $prop {
            fn log(&self, tag: &str, logger: &mut cvlr::log::CvlrLogger) {
                use cvlr::log::cvlr_log_with;
                logger.log_scope_start(tag);
                let __self = self;
                $(impl_cvlr_log!(@field __self, logger, $field);)*
                logger.log_scope_end(tag);
            }
        }
    };

    (@field $self:ident, $logger:ident, $field:ident) => {
        cvlr_log_with(stringify!($field), &$self.$field, $logger);
    };
}

#[macro_export]
macro_rules! impl_cvlr_nondet {
    ($prop:path $(, $field:ident)* $(,)?) => {
        impl cvlr::nondet::Nondet for $prop {
            fn nondet() -> Self {
                Self {
                    $($field: nondet(),)*
                }
            }
        }
    };
}

#[macro_export]
macro_rules! cvlr_inv {
    ($s:ident -> $( $e:expr ),* $(,)?) => {
        #[inline(always)]
        fn assume_pre(&self) {
            let $s = self;
            $(
                cvlr_assume!($e);
            )*
        }
        #[inline(always)]
        fn check_post(&self, _old: &Self) {
            let $s = self;
            $(
                cvlr_assert!($e);
            )*
        }
    };
}