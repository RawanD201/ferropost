//! Spintax: `{Hello|Hi|Hey}` picks one option per message (Go:
//! `batch_mail/spintax.go`).
//!
//! Same rules as Go: text inside HTML tags and `<style>`/`<script>` blocks
//! is left alone, braces may nest (the whole block is split on every `|`,
//! as Go did), options are trimmed and empty ones dropped, and a block
//! without `|` is kept as written. Go re-scanned the text before every
//! position to know whether it was inside a tag, which is quadratic in the
//! message size; this tracks it in one pass.

use rand::Rng;

/// Replaces every spintax block with a random option.
pub fn spin(content: &str, rng: &mut impl Rng) -> String {
    if !content.contains('{') || !content.contains('|') {
        return content.to_owned();
    }
    let bytes = content.as_bytes();
    let mut out = String::with_capacity(content.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            let skip = raw_block_len(content, i).unwrap_or_else(|| tag_len(content, i));
            out.push_str(&content[i..i + skip]);
            i += skip;
            continue;
        }
        if bytes[i] == b'{'
            && let Some((len, choice)) = block_at(content, i, rng)
        {
            out.push_str(choice);
            i += len;
            continue;
        }
        // Copy one whole character (the content is UTF-8).
        let ch_len = content[i..].chars().next().map_or(1, char::len_utf8);
        out.push_str(&content[i..i + ch_len]);
        i += ch_len;
    }
    out
}

/// True when the content has at least one block that would be spun.
pub fn has_spintax(content: &str) -> bool {
    struct First;
    impl rand::RngCore for First {
        fn next_u32(&mut self) -> u32 {
            0
        }
        fn next_u64(&mut self) -> u64 {
            0
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            dest.fill(0);
            Ok(())
        }
    }
    spin(content, &mut First) != content
}

/// Length of a `<style>...</style>` or `<script>...</script>` block
/// starting at `pos`, if one does.
fn raw_block_len(content: &str, pos: usize) -> Option<usize> {
    for tag in ["style", "script"] {
        let rest = &content[pos..];
        let open = format!("<{tag}");
        if rest.len() >= open.len()
            && rest.as_bytes()[..open.len()].eq_ignore_ascii_case(open.as_bytes())
            && rest
                .as_bytes()
                .get(open.len())
                .is_none_or(|b| matches!(b, b'>' | b' ' | b'\t' | b'\n'))
        {
            // Case-insensitive like the opening tag (Go matched `</script>`
            // case-sensitively, so `<SCRIPT>` blocks were spun).
            let close = format!("</{tag}>");
            if let Some(end) = rest.to_ascii_lowercase().find(&close) {
                return Some(end + close.len());
            }
        }
    }
    None
}

/// Length of the tag starting at `pos` (through `>`, or to the end).
fn tag_len(content: &str, pos: usize) -> usize {
    content[pos..]
        .find('>')
        .map_or(content.len() - pos, |end| end + 1)
}

/// The block starting at `pos`: its length and the chosen option.
fn block_at<'a>(content: &'a str, pos: usize, rng: &mut impl Rng) -> Option<(usize, &'a str)> {
    let bytes = content.as_bytes();
    let mut depth = 1;
    let mut i = pos + 1;
    while i < bytes.len() && depth > 0 {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => depth -= 1,
            _ => {}
        }
        i += 1;
    }
    if depth != 0 {
        return None;
    }
    let inner = &content[pos + 1..i - 1];
    if !inner.contains('|') {
        return None;
    }
    let options: Vec<&str> = inner
        .split('|')
        .map(str::trim)
        .filter(|o| !o.is_empty())
        .collect();
    if options.is_empty() {
        return None;
    }
    Some((i - pos, options[rng.gen_range(0..options.len())]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn spun(content: &str) -> String {
        spin(content, &mut StdRng::seed_from_u64(1))
    }

    #[test]
    fn picks_one_option() {
        for _ in 0..20 {
            let out = spin("{Hello|Hi|Hey} there", &mut rand::thread_rng());
            assert!(["Hello there", "Hi there", "Hey there"].contains(&out.as_str()));
        }
    }

    #[test]
    fn leaves_markup_alone() {
        let html = "<p style=\"color:{red|blue}\">{A|A}</p><style>.x{a|b}</style><SCRIPT>if(x){a|b}</SCRIPT>";
        assert_eq!(
            spun(html),
            "<p style=\"color:{red|blue}\">A</p><style>.x{a|b}</style><SCRIPT>if(x){a|b}</SCRIPT>"
        );
    }

    #[test]
    fn go_edge_cases() {
        assert_eq!(spun("{no pipe} {|} {a| }"), "{no pipe} {|} a");
        assert_eq!(spun("unclosed {a|b"), "unclosed {a|b");
        assert_eq!(spun("héllo {ünï|ünï} ✓"), "héllo ünï ✓");
        assert!(has_spintax("x {a|b}"));
        assert!(!has_spintax(
            "<b>{a|b}</b>".replace("{a|b}", "{ab}").as_str()
        ));
    }

    #[test]
    fn large_input_is_linear() {
        let html = "<td class=\"x\">{a|b}</td>".repeat(50_000);
        let start = std::time::Instant::now();
        let out = spun(&html);
        assert_eq!(out.len(), html.len() - 4 * 50_000);
        assert!(start.elapsed().as_secs() < 2, "one pass over ~1 MB");
    }
}
