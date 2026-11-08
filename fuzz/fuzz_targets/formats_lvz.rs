#![no_main]
//! `.lvz` archives and their object sections. Whatever parses must rewrite and
//! parse back to the same value; section inflation must not panic.

use libfuzzer_sys::fuzz_target;
use oss_core_fuzz::assert_stable;
use oss_formats::{Lvz, ObjectSection};

fuzz_target!(|data: &[u8]| {
    let Some((&which, data)) = data.split_first() else {
        return;
    };
    if which & 1 == 0 {
        if let Ok(lvz) = Lvz::parse(data) {
            assert_stable(&lvz, Lvz::to_bytes, Lvz::parse);
            for section in &lvz.sections {
                let _ = section.is_object_section();
                let _ = section.data();
            }
            if let Ok(objects) = lvz.object_sections() {
                for o in &objects {
                    assert_stable(o, ObjectSection::to_bytes, ObjectSection::parse);
                }
            }
        }
    } else if let Ok(objects) = ObjectSection::parse(data) {
        assert_stable(&objects, ObjectSection::to_bytes, ObjectSection::parse);
    }
});
