// SPDX-FileCopyrightText: 2014 John Hawthorn
//
// SPDX-License-Identifier: MIT

window.fzy = (function() {
    var SCORE_MIN = -Infinity;
    var SCORE_MAX = Infinity;

    var SCORE_GAP_LEADING = -0.005
    var SCORE_GAP_TRAILING = -0.005
    var SCORE_GAP_INNER = -0.01
    var SCORE_MATCH_CONSECUTIVE = 1.0
    var SCORE_MATCH_SLASH = 0.9
    var SCORE_MATCH_WORD = 0.8
    var SCORE_MATCH_CAPITAL = 0.7
    var SCORE_MATCH_DOT = 0.6

    function islower(s) {
        return s.toLowerCase() === s;
    }

    function isupper(s) {
        return s.toUpperCase() === s;
    }

    function precompute_bonus(haystack) {
        /* Which positions are beginning of words */
        var m = haystack.length;
        var match_bonus = new Array(m);

        var last_ch = '/';
        for (var i = 0; i < m; i++) {
            var ch = haystack[i];

            if (last_ch === '/') {
                match_bonus[i] = SCORE_MATCH_SLASH;
            } else if (last_ch === '-' || last_ch === '_' || last_ch === ' ') {
                match_bonus[i] = SCORE_MATCH_WORD;
            } else if (last_ch === '.') {
                match_bonus[i] = SCORE_MATCH_DOT;
            } else if (islower(last_ch) && isupper(ch)) {
                match_bonus[i] = SCORE_MATCH_CAPITAL;
            } else {
                match_bonus[i] = 0;
            }

            last_ch = ch;
        }

        return match_bonus;
    }

    function compute(needle, haystack, D, M) {
        var n = needle.length;
        var m = haystack.length;

        var match_bonus = precompute_bonus(haystack, match_bonus);

        /*
        * D[][] Stores the best score for this position ending with a match.
        * M[][] Stores the best possible score at this position.
        */

        for (var i = 0; i < n; i++) {
            D[i] = new Array(m);
            M[i] = new Array(m);

            var prev_score = SCORE_MIN;
            var gap_score = i === n - 1 ? SCORE_GAP_TRAILING : SCORE_GAP_INNER;

            for (var j = 0; j < m; j++) {
                if (needle[i] === haystack[j]) {
                    var score = SCORE_MIN;
                    if (!i) {
                        score = (j * SCORE_GAP_LEADING) + match_bonus[j];
                    } else if (j) { /* i > 0 && j > 0*/
                        score = Math.max(
                            M[i - 1][j - 1] + match_bonus[j],

                            /* consecutive match, doesn't stack with match_bonus */
                            D[i - 1][j - 1] + SCORE_MATCH_CONSECUTIVE);
                    }
                    D[i][j] = score;
                    M[i][j] = prev_score = Math.max(score, prev_score + gap_score);
                } else {
                    D[i][j] = SCORE_MIN;
                    M[i][j] = prev_score = prev_score + gap_score;
                }
            }
        }
    }

    function score(needle, haystack) {
        var n = needle.length;
        var m = haystack.length;

        if (!n || !m)
            return SCORE_MIN;

        if (n === m) {
            /* Since this method can only be called with a haystack which
            * matches needle. If the lengths of the strings are equal the
            * strings themselves must also be equal (ignoring case).
            */
            return SCORE_MAX;
        }

        if (m > 1024) {
            /*
            * Unreasonably large candidate: return no score
            * If it is a valid match it will still be returned, it will
            * just be ranked below any reasonably sized candidates
            */
            return SCORE_MIN;
        }

        var D = new Array(n);
        var M = new Array(n);

        compute(needle, haystack, D, M)

        return M[n - 1][m - 1];
    }

    function positions(needle, haystack) {
        var n = needle.length;
        var m = haystack.length;

        var positions = new Array(n);

        if (!n || !m)
            return positions;

        if (n === m) {
            for (var i = 0; i < n; i++)
                positions[i] = i;
            return positions;
        }

        if (m > 1024) {
            return positions;
        }

        var D = new Array(n);
        var M = new Array(n);

        compute(needle, haystack, D, M)

        /* backtrack to find the positions of optimal matching */
        var match_required = false;

        for (var i = n - 1, j = m - 1; i >= 0; i--) {
            for (; j >= 0; j--) {
                /*
                * There may be multiple paths which result in
                * the optimal weight.
                *
                * For simplicity, we will pick the first one
                * we encounter, the latest in the candidate
                * string.
                */
                if (D[i][j] !== SCORE_MIN &&
                    (match_required || D[i][j] === M[i][j])) {
                    /* If this score was determined using
                    * SCORE_MATCH_CONSECUTIVE, the
                    * previous character MUST be a match
                    */
                    match_required =
                        i && j &&
                        M[i][j] === D[i - 1][j - 1] + SCORE_MATCH_CONSECUTIVE;
                    positions[i] = j--;
                    break;
                }
            }
        }

        return positions;
    }

    function hasMatch(needle, haystack) {
        var l = needle.length
        for (var i = 0, j = 0; i < l; i += 1) {
            j = haystack.indexOf(needle[i], j) + 1
            if (j === 0) return false
        }
        return true
    }

    function filter(needle, items, selector) {
        const isCaseSensitive = needle.toLowerCase() !== needle;
        const actualNeedle = isCaseSensitive ? needle : needle.toLowerCase();
        const filteredItems = items.reduce((results, item) => {
            const haystack = isCaseSensitive ? selector(item) : selector(item).toLowerCase();
            if (hasMatch(actualNeedle, haystack))
                results.push({ item, score: score(needle, haystack) })
            return results;
        }, [])
        filteredItems.sort((a, b) => b.score - a.score)
        return filteredItems;
    }

    return {
        /* constants */
        SCORE_MIN,
        SCORE_MAX,

        SCORE_GAP_LEADING,
        SCORE_GAP_TRAILING,
        SCORE_GAP_INNER,
        SCORE_MATCH_CONSECUTIVE,
        SCORE_MATCH_SLASH,
        SCORE_MATCH_WORD,
        SCORE_MATCH_CAPITAL,
        SCORE_MATCH_DOT,

        /* functions */
        score,
        positions,
        hasMatch,
        filter,
    }
})();
