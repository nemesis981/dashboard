"""
Passphrase generator + validator.

generate() produces a memorable-but-strong passphrase using the `secrets` module
(cryptographically secure). validate() enforces minimum strength on user-chosen
passwords. No external deps.
"""

import re
import secrets

# ~200 common, unambiguous, recognizable words. All lowercase, 4-8 chars, no
# homophones, no offensive words. Curated for readability when spoken/typed.
WORDLIST = [
    "apple", "amber", "anchor", "arrow", "autumn", "bacon", "badge", "bamboo",
    "banana", "basket", "beacon", "beach", "bridge", "bronze", "bubble", "bucket",
    "buffalo", "button", "cabin", "cactus", "camel", "candle", "canyon", "carbon",
    "carpet", "castle", "cedar", "cherry", "chimney", "circle", "clever", "clover",
    "cobra", "coffee", "comet", "copper", "coral", "cosmic", "cotton", "cougar",
    "cradle", "crayon", "crystal", "dancer", "denim", "desert", "diamond", "dinner",
    "dolphin", "donkey", "dragon", "dynamo", "eagle", "ember", "engine", "expert",
    "fabric", "falcon", "feather", "fennel", "ferry", "fiber", "fiddle", "finch",
    "flannel", "flower", "forest", "fossil", "fountain", "frame", "frost", "galaxy",
    "garden", "gentle", "ginger", "glacier", "granite", "gravel", "guitar", "hammer",
    "harbor", "hazel", "helmet", "hickory", "honey", "hornet", "ignite", "indigo",
    "island", "ivory", "jacket", "jaguar", "jasmine", "jelly", "jersey", "jungle",
    "kettle", "kitten", "koala", "ladder", "lagoon", "lantern", "lemon", "leopard",
    "lily", "lizard", "lobster", "locket", "lotus", "lumber", "magnet", "mango",
    "maple", "marble", "marigold", "meadow", "melon", "mellow", "metro", "mirror",
    "mitten", "monkey", "moose", "mosaic", "muffin", "mushroom", "mustard", "nectar",
    "needle", "nickel", "noble", "nugget", "ocean", "olive", "onyx", "orchid",
    "otter", "oxford", "oyster", "paddle", "panda", "parrot", "peach", "pebble",
    "pelican", "pepper", "pewter", "pickle", "pigeon", "pillow", "pirate", "planet",
    "plasma", "pocket", "pony", "poppy", "potato", "prairie", "pretzel", "puffin",
    "pumpkin", "puzzle", "quartz", "quilt", "rabbit", "radish", "raisin", "ranch",
    "raven", "ribbon", "ridge", "river", "robin", "rocket", "rubber", "ruby",
    "saddle", "salmon", "sandal", "sapphire", "scarf", "shadow", "shark", "shovel",
    "silver", "simple", "sketch", "sleeve", "slipper", "smoke", "soda", "spark",
    "sparrow", "spider", "spinach", "spruce", "stable", "station", "stencil", "stone",
    "stork", "storm", "summer", "sunny", "syrup", "table", "tango", "teapot",
    "temple", "thunder", "tiger", "timber", "toffee", "tomato", "topaz", "tornado",
    "tower", "trophy", "tulip", "tundra", "turtle", "umbrella", "unicorn", "valley",
    "velvet", "vinegar", "violet", "voyage", "walnut", "walrus", "wander", "wasabi",
    "waffle", "willow", "window", "winter", "wizard", "wombat", "yellow", "yogurt",
    "zebra", "zephyr", "zigzag", "zipper",
]

_SEPARATORS = ["-", "_", ".", "~", "!", "@", "#"]


def generate() -> str:
    """
    Generate a passphrase: word{sep}word{sep}Word{sep}word{sep}NN
    - 4 words from the wordlist
    - exactly one word randomly capitalized (required)
    - one separator (randomly chosen) used throughout
    - a 2-digit number (10-99) appended
    - cryptographically secure (secrets module)
    Returns the passphrase string.
    """
    words = [secrets.choice(WORDLIST) for _ in range(4)]
    cap = secrets.randbelow(4)                 # index of the word to capitalize
    words[cap] = words[cap].capitalize()
    sep = secrets.choice(_SEPARATORS)
    number = secrets.randbelow(90) + 10        # 10-99
    return sep.join(words) + sep + str(number)


def validate(password: str):
    """
    Validate a user-supplied password meets the minimum requirements:
    - at least 4 alphabetic segments (words)
    - at least one capital letter
    - at least one digit
    - at least one non-alphanumeric character (separator)
    - minimum 16 characters total
    Returns (True, None) or (False, reason_string).
    """
    if not password or len(password) < 16:
        return False, "Password must be at least 16 characters long."
    if len(re.findall(r"[A-Za-z]+", password)) < 4:
        return False, "Password must contain at least 4 words (letter groups)."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one capital letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "Password must contain at least one separator (e.g. - _ . ! @ #)."
    return True, None
