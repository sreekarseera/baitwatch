// GENERATED FILE — do not edit by hand. Run `python3 tools/build_confusables.py`.
//
// Source: Unicode Security Mechanisms (UTS #39), confusables.txt
// https://www.unicode.org/Public/security/latest/confusables.txt
// © Unicode, Inc. Used under the Unicode Terms of Use
// (https://www.unicode.org/terms_of_use.html). This is a filtered derivation,
// not the data file: 273 of the source's 6565 mappings survive.
//
// Every mapping folds a non-ASCII character onto exactly one ASCII letter, so
// a string can be compared against a brand name. Mappings that fold toward
// anything else were dropped, as were the scripts a fold would damage —
// Devanagari above all, because the Hindi rules in engine/heuristics.js match
// it literally. tools/build_confusables.py carries the full reasoning.
//
// Included:
//     44  Cyrillic, Cyrillic Supplement
//     29  Cherokee
//     28  Greek and Coptic
//     26  Lisu
//     25  Coptic
//     14  Armenian
//     14  Latin-1 Supplement, Latin Extended-A/B
//     10  Carian
//     10  Phonetic Extensions
//      9  Latin Extended-D
//      9  Lycian
//      8  Elbasan
//      8  IPA Extensions
//      8  Latin Extended-E
//      8  Old Italic
//      7  Cherokee Supplement
//      7  Deseret
//      6  Osage
//      2  Latin Extended Additional
//      1  Cyrillic Extended-B

// Source and replacement, alternating. A `{"а": "a", ...}` object literal
// would spend eight bytes per entry on quotes, colons and commas; this spends
// two characters, and the pairs are rebuilt once at module load.
const PAIRS =
  "×xþpıiƄbƍgƒfƖlƦRƷeƼsƽsƿpǀlȜeɑaɡgɣyɩiɪiɯwʋuʏyͿJΑAΒBΕEΖZΗHΙlΚKΜMΝNΟOΡPΤTΥYΧXαaγyιiνvοoρpσoυuϜFϭoϳjϸpϺMЅSІlЈJАAВBЕEЗeКKМMНHОOРPСCТTУYХXЬbаaгrеeоoрpсcуyхxшwѕsіiјjѡwѴVѵvҮYүyһhҽeӀlӏlӠeԁdԌGԛqԜWԝwՍUՏSՕOաwգqզqհhոnռnսuցgւiքfօoᎠDᎡRᎢTᎥiᎩYᎪAᎫJᎬEᎳWᎷMᎻHᎽYᏀGᏂhᏃZᏎaᏏbᏒRᏔWᏕSᏙVᏚSᏞLᏟCᏢPᏦKᏧdᏳGᏴBᴄcᴏoᴑoᴜuᴠvᴡwᴢzᴦrᶃgᶌyẝfỿyⲂBⲅrⲎHⲒlⲓiⲔKⲘMⲚNⲜeⲞOⲟoⲢPⲣpⲤCⲥcⲦTⲨYⲩyⲬXⲽwⳄeⳌeⳎPⳏpⳐLꓐBꓑPꓒdꓓDꓔTꓖGꓗKꓙJꓚCꓜZꓝFꓟMꓠNꓡLꓢSꓣRꓦVꓧHꓪWꓫXꓬYꓮAꓰEꓲlꓳOꓴUꙇiꜱsꝪeꞘFꞙfꞟuꞫeꞲJꞳXꞴBꬲeꬵfꬽoꭇrꭈrꭎuꭒuꭚyꭵiꮁrꮃwꮓzꮩvꮪsꮯc𐊂B𐊆E𐊇F𐊊l𐊐X𐊒O𐊕P𐊖S𐊗T𐊠A𐊡B𐊢C𐊥F𐊫O𐊰M𐊱T𐊲Y𐊴X𐋏H𐌁B𐌂C𐌉l𐌑M𐌕T𐌗X𐌠l𐌢X𐐄O𐐕C𐐛L𐐠S𐐬o𐐽c𐑈s𐒴R𐓂O𐓎U𐓒t𐓪o𐓶u𐔓N𐔖O𐔘K𐔜C𐔝V𐔥F𐔦L𐔧X";

// Array.from iterates by code point, not by UTF-16 unit — the Deseret, Osage
// and Carian sources are astral, and indexing PAIRS[i] would hand back half a
// surrogate pair.
const CODEPOINTS = Array.from(PAIRS);

export const CONFUSABLES = new Map();
for (let i = 0; i < CODEPOINTS.length; i += 2) {
  CONFUSABLES.set(CODEPOINTS[i], CODEPOINTS[i + 1]);
}

// One character class over every source, so folding is a single pass rather
// than a lookup per character. No escaping is needed: every source is
// non-ASCII by construction, so none of them can be `]`, `^`, `-` or `\`.
export const CONFUSABLE_RE = new RegExp(
  `[${[...CONFUSABLES.keys()].join("")}]`,
  "gu"
);
