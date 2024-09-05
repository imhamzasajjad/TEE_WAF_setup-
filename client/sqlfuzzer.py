import random
import re
import sqlparse
from wafamole.payloadfuzzer.fuzz_utils import (
    replace_random,
    filter_candidates,
    random_string,
    num_tautology,
    string_tautology,
    num_contradiction,
    string_contradiction,
)


def reset_inline_comments(payload: str):
    """
    Removes a randomly chosen multi-line comment.

    Arguments:
        payload: query payload (string)

    Returns:
        str: payload modified
    """
    positions = list(re.finditer(r"/\*[^(/\*|\*/)]*\*/", payload))

    if not positions:
        return payload

    pos = random.choice(positions).span()

    replacement = "/**/"

    new_payload = payload[: pos[0]] + replacement + payload[pos[1] :]

    return new_payload


def logical_invariant(payload: str):
    """
    Adds a logical invariant condition to the payload.

    Arguments:
        payload: query payload (string)

    Returns:
        str: payload modified
    """
    num_tautologies = [r"\b(\d+)\b", r"\b(\d+)(\s*=\s*|\s+(?i:like)\s+)\1\b"]
    string_tautologies = [
        r'(\'|\")([a-zA-Z]{1}[\w#@$]*)\1(\s*=\s*|\s+(?i:like)\s+)(\'|\")\2\4',
        r'(\'|\")([a-zA-Z]{1}[\w#@$]*)\1(\s*(!=|<>)\s*|\s+(?i:not like)\s+)(\'|\")(?!\2)([a-zA-Z]{1}[\w#@$]*)\5',
    ]

    candidates = num_tautologies + string_tautologies

    for pattern in candidates:
        matches = list(re.finditer(pattern, payload))
        if matches:
            match = random.choice(matches)
            pos = match.span()
            replacement = random.choice([
                " AND 1",  # Example of modification
                " OR 0",   # Another example of modification
                "(SELECT 1)",  # Yet another example
            ])
            new_payload = payload[: pos[0]] + replacement + payload[pos[1] :]
            return new_payload

    return payload


def change_tautologies(payload: str):
    """
    Replaces a randomly chosen numeric/string tautology with another one.

    Arguments:
        payload: query payload (string)

    Returns:
        str: payload modified
    """
    num_tautologies = [r'\b(\d+)\b', r'\b(\d+)(\s*=\s*|\s+(?i:like)\s+)\1\b']
    string_tautologies = [
        r'(\'|\")([a-zA-Z]{1}[\w#@$]*)\1(\s*=\s*|\s+(?i:like)\s+)(\'|\")\2\4',
        r'(\'|\")([a-zA-Z]{1}[\w#@$]*)\1(\s*(!=|<>)\s*|\s+(?i:not like)\s+)(\'|\")(?!\2)([a-zA-Z]{1}[\w#@$]*)\5',
    ]

    candidates = num_tautologies + string_tautologies

    for pattern in candidates:
        matches = list(re.finditer(pattern, payload))
        if matches:
            match = random.choice(matches)
            pos = match.span()
            replacement = random.choice([
                num_tautology(),  # Replace with a numeric tautology
                string_tautology(),  # Replace with a string tautology
            ])
            new_payload = payload[: pos[0]] + replacement + payload[pos[1] :]
            return new_payload

    return payload


def spaces_to_comments(payload: str):
    """
    Replaces a randomly chosen space character with a multi-line comment (and vice-versa).

    Arguments:
        payload: query payload (string)

    Returns:
        str: payload modified
    """
    symbols = {" ": ["/**/"], "/**/": [" "]}

    symbols_in_payload = filter_candidates(symbols, payload)

    if not symbols_in_payload:
        return payload

    candidate_symbol = random.choice(symbols_in_payload)
    replacements = symbols[candidate_symbol]
    candidate_replacement = random.choice(replacements)

    return replace_random(payload, re.escape(candidate_symbol), candidate_replacement)


def spaces_to_whitespaces_alternatives(payload: str):
    """
    Replaces a randomly chosen whitespace character with another one.

    Arguments:
        payload: query payload (string)

    Returns:
        str: payload modified
    """
    symbols = {
        " ": ["\t", "\n"],
        "\t": [" ", "\n"],
        "\n": ["\t", " "],
       # "\f": ["\t", "\n"]
        #"\v": ["\t", "\n", "\f", " "],
       # "\xa0": ["\t", "\n", "\f", "\v", " "],
    }

    symbols_in_payload = filter_candidates(symbols, payload)

    if not symbols_in_payload:
        return payload

    candidate_symbol = random.choice(symbols_in_payload)
    replacements = symbols[candidate_symbol]
    candidate_replacement = random.choice(replacements)

    return replace_random(payload, re.escape(candidate_symbol), candidate_replacement)


def random_case(payload: str):
    """
    Randomly changes the capitalization of the SQL keywords in the input payload.

    Arguments:
        payload: query payload (string)

    Returns:
        str: payload modified
    """
    tokens = []
    try:
        parsed_payload = sqlparse.parse(payload)
    except Exception:
        return payload
    for t in parsed_payload:
        tokens.extend(list(t.flatten()))

    sql_keywords = set(sqlparse.keywords.KEYWORDS_COMMON.keys())

    new_payload = []
    for token in tokens:
        if token.value.upper() in sql_keywords:
            new_token = ''.join([c.swapcase() if random.random() > 0.5 else c for c in token.value])
            new_payload.append(new_token)
        else:
            new_payload.append(token.value)

    return "".join(new_payload)


def comment_rewriting(payload: str):
    """
    Changes the content of a randomly chosen in-line or multi-line comment.

    Arguments:
        payload: query payload (string)

    Returns:
        str: payload modified
    """
    p = random.random()

    if p < 0.5 and ("#" in payload or "-- " in payload):
        return payload + random_string(2)
    elif p >= 0.5 and re.search(r"/\*[^(/\*|\*/)]*\*/", payload):
        return replace_random(payload, r"/\*[^(/\*|\*/)]*\*/", "/*" + random_string() + "*/")
    else:
        return payload


def swap_int_repr(payload: str):
    """
    Changes the representation of a randomly chosen numerical constant with an equivalent one.

    Arguments:
        payload: query payload (string)

    Returns:
        str: payload modified
    """
    candidates = list(re.finditer(r'\b\d+\b', payload))

    if not candidates:
        return payload

    candidate_pos = random.choice(candidates).span()

    candidate = payload[candidate_pos[0]: candidate_pos[1]]

    replacements = [
        hex(int(candidate)),
        "(SELECT {})".format(candidate),
    ]

    replacement = random.choice(replacements)

    return payload[: candidate_pos[0]] + replacement + payload[candidate_pos[1]:]


def swap_keywords(payload: str):
    """
    Replaces a randomly chosen SQL operator with a semantically equivalent one.

    Arguments:
        payload: query payload (string)

    Returns:
        str: payload modified
    """
    replacements = {
        "||": [" OR ", " or "],
        "OR": ["||", "or"],
        "&&": [" AND ", " and "],
        "AND": ["&&", "and"],
        "<>": ["!=", " NOT LIKE ", " not like "],
        "!=": ["<>", " NOT LIKE ", " not like "],
        "NOT LIKE": ["not like"],
        "=": [" LIKE ", " like "],
        "LIKE": ["like"],
    }

    tokens = []
    try:
        parsed_payload = sqlparse.parse(payload)
    except Exception:
        return payload
    for t in parsed_payload:
        tokens.extend(list(t.flatten()))

    indices = [idx for idx, token in enumerate(tokens) if token.value in replacements]
    if not indices:
        return payload

    target_idx = random.choice(indices)
    new_payload = "".join([
        random.choice(replacements[token.value]) if idx == target_idx else token.value for idx, token in enumerate(tokens)
    ])

    return new_payload


class SqlFuzzer(object):
    """SqlFuzzer class"""

    strategies = [
        reset_inline_comments,
        logical_invariant,
        change_tautologies,
        spaces_to_comments,
        spaces_to_whitespaces_alternatives,
        random_case,
        comment_rewriting,
        swap_int_repr,
        swap_keywords,
    ]

    def __init__(self, payload):
        self.initial_payload = payload
        self.payload = payload

    def fuzz(self):
        random.shuffle(self.strategies)  # Shuffle to ensure each strategy runs exactly once
        for strategy in self.strategies:
            self.payload = strategy(self.payload)
        return self.payload

    def current(self):
        return self.payload

    def reset(self):
        self.payload = self.initial_payload
        return self.payload