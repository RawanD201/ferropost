//! Login captcha (Go: `base64Captcha`, a PNG). Four characters drawn as
//! SVG strokes, each with its own rotation, scale and offset, over noise
//! curves; the console shows it as a data URI either way. Answers live in
//! Redis for three minutes and work once (Go kept them in process memory).

use base64::Engine;
use rand::Rng;

use crate::state::AppState;

/// Go's character set: no look-alikes such as 0/o, 1/l, 2/z, 6/b.
const ALPHABET: &[u8] = b"34578abcdefhjkmnprstuvwxy";
const LENGTH: usize = 4;
pub const TTL_SECS: i64 = 180;
const WIDTH: f32 = 200.0;
const HEIGHT: f32 = 75.0;

type Stroke = &'static [(f32, f32)];

/// Glyphs as strokes on a 4 x 6 grid.
fn glyph(c: u8) -> &'static [Stroke] {
    match c {
        b'3' => &[
            &[(0., 0.), (4., 0.), (4., 3.), (1., 3.)],
            &[(4., 3.), (4., 6.), (0., 6.)],
        ],
        b'4' => &[&[(3., 6.), (3., 0.), (0., 4.), (4., 4.)]],
        b'5' => &[&[(4., 0.), (0., 0.), (0., 3.), (4., 3.), (4., 6.), (0., 6.)]],
        b'7' => &[&[(0., 0.), (4., 0.), (1., 6.)]],
        b'8' => &[
            &[(0., 0.), (4., 0.), (4., 6.), (0., 6.), (0., 0.)],
            &[(0., 3.), (4., 3.)],
        ],
        b'a' => &[&[(0., 2.), (4., 2.), (4., 6.), (0., 6.), (0., 4.), (4., 4.)]],
        b'b' => &[&[(0., 0.), (0., 6.), (4., 6.), (4., 3.), (0., 3.)]],
        b'c' => &[&[(4., 2.), (0., 2.), (0., 6.), (4., 6.)]],
        b'd' => &[&[(4., 0.), (4., 6.), (0., 6.), (0., 3.), (4., 3.)]],
        b'e' => &[&[(0., 4.), (4., 4.), (4., 2.), (0., 2.), (0., 6.), (4., 6.)]],
        b'f' => &[&[(4., 0.), (2., 0.), (2., 6.)], &[(0., 3.), (4., 3.)]],
        b'h' => &[&[(0., 0.), (0., 6.)], &[(0., 3.), (4., 3.), (4., 6.)]],
        b'j' => &[&[(3., 2.), (3., 6.), (0., 6.)], &[(3., 0.), (3., 0.6)]],
        b'k' => &[&[(0., 0.), (0., 6.)], &[(4., 2.), (0., 4.), (4., 6.)]],
        b'm' => &[
            &[(0., 6.), (0., 2.), (4., 2.), (4., 6.)],
            &[(2., 2.), (2., 6.)],
        ],
        b'n' => &[&[(0., 6.), (0., 2.), (4., 2.), (4., 6.)]],
        b'p' => &[&[(0., 6.), (0., 2.), (4., 2.), (4., 4.5), (0., 4.5)]],
        b'r' => &[&[(0., 6.), (0., 2.), (4., 2.)]],
        b's' => &[&[(4., 2.), (0., 2.), (0., 4.), (4., 4.), (4., 6.), (0., 6.)]],
        b't' => &[&[(2., 0.), (2., 6.), (4., 6.)], &[(0., 2.), (4., 2.)]],
        b'u' => &[&[(0., 2.), (0., 6.), (4., 6.), (4., 2.)]],
        b'v' => &[&[(0., 2.), (2., 6.), (4., 2.)]],
        b'w' => &[&[(0., 2.), (1., 6.), (2., 4.), (3., 6.), (4., 2.)]],
        b'x' => &[&[(0., 2.), (4., 6.)], &[(4., 2.), (0., 6.)]],
        b'y' => &[&[(0., 2.), (2., 4.), (4., 2.)], &[(2., 4.), (2., 6.)]],
        _ => &[],
    }
}

/// A random answer from the alphabet.
pub fn random_answer(rng: &mut impl Rng) -> String {
    (0..LENGTH)
        .map(|_| char::from(ALPHABET[rng.gen_range(0..ALPHABET.len())]))
        .collect()
}

/// The SVG for `answer`.
pub fn render(answer: &str, rng: &mut impl Rng) -> String {
    const COLORS: [&str; 5] = ["#3b2f8f", "#8f2f5a", "#2f6f8f", "#5a8f2f", "#8f5a2f"];
    let mut svg = format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" viewBox="0 0 {WIDTH} {HEIGHT}"><rect width="100%" height="100%" fill="#eeedf5"/>"##
    );
    for _ in 0..3 {
        let (y0, y1) = (rng.gen_range(10.0..65.0), rng.gen_range(10.0..65.0));
        let (cx, cy) = (rng.gen_range(50.0..150.0), rng.gen_range(0.0..75.0));
        svg.push_str(&format!(
            r#"<path d="M0 {y0:.1} Q{cx:.1} {cy:.1} {WIDTH} {y1:.1}" stroke="{}" stroke-width="1.5" fill="none" opacity="0.6"/>"#,
            COLORS[rng.gen_range(0..COLORS.len())]
        ));
    }
    for (i, c) in answer.bytes().enumerate() {
        let scale = rng.gen_range(6.0..8.0f32);
        let x = 22.0 + i as f32 * 44.0 + rng.gen_range(-4.0..4.0f32);
        let y = 14.0 + rng.gen_range(-4.0..4.0f32);
        let angle = rng.gen_range(-20.0..20.0f32);
        let (cx, cy) = (x + 2.0 * scale, y + 3.0 * scale);
        let d: String = glyph(c)
            .iter()
            .map(|stroke| {
                stroke
                    .iter()
                    .enumerate()
                    .map(|(n, (gx, gy))| {
                        format!(
                            "{}{:.1} {:.1}",
                            if n == 0 { "M" } else { "L" },
                            x + gx * scale,
                            y + gy * scale
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect::<Vec<_>>()
            .join(" ");
        svg.push_str(&format!(
            r#"<path d="{d}" transform="rotate({angle:.1} {cx:.1} {cy:.1})" stroke="{}" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round" fill="none"/>"#,
            COLORS[rng.gen_range(0..COLORS.len())]
        ));
    }
    for _ in 0..30 {
        svg.push_str(&format!(
            r#"<circle cx="{:.1}" cy="{:.1}" r="{:.1}" fill="{}" opacity="0.5"/>"#,
            rng.gen_range(0.0..WIDTH),
            rng.gen_range(0.0..HEIGHT),
            rng.gen_range(0.5..1.8f32),
            COLORS[rng.gen_range(0..COLORS.len())]
        ));
    }
    svg.push_str("</svg>");
    svg
}

/// A new captcha: its ID and the image as a data URI.
pub async fn issue(state: &AppState) -> anyhow::Result<(String, String)> {
    let mut rng = rand::rngs::OsRng;
    let answer = random_answer(&mut rng);
    let id = {
        use rand::RngCore;
        let mut bytes = [0u8; 12];
        rng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    };
    ferropost_store::tokens::store_captcha(&state.store.redis, &id, &answer, TTL_SECS).await?;
    let svg = render(&answer, &mut rng);
    let uri = format!(
        "data:image/svg+xml;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(svg)
    );
    Ok((id, uri))
}

/// Checks and uses up a captcha (letters in either case).
pub async fn check(state: &AppState, id: &str, code: &str) -> anyhow::Result<bool> {
    let answer = ferropost_store::tokens::take_captcha(&state.store.redis, id).await?;
    Ok(answer.is_some_and(|a| a.eq_ignore_ascii_case(code.trim())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_character_is_drawn() {
        for &c in ALPHABET {
            assert!(!glyph(c).is_empty(), "{}", char::from(c));
        }
        let mut rng = rand::rngs::OsRng;
        assert_eq!(random_answer(&mut rng).len(), LENGTH);
        let svg = render("3kx7", &mut rng);
        assert!(svg.starts_with("<svg") && svg.ends_with("</svg>"));
        assert_eq!(svg.matches("stroke-width=\"3.2\"").count(), LENGTH);
        assert!(
            !svg.contains("3kx7"),
            "the answer is not in the markup as text"
        );
    }
}
