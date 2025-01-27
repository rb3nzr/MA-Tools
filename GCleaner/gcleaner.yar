rule GCleaner
{
    meta:
        author = "rb3nzr"
        date = "2025-01-09"
        description = "Detects GCleaner"
        hash = "a883940150a872c5ac33249ca8523e75ee98f4ace0bf1ad17d9d16c7edd78f8c"

    strings:
        $s1 = { 0F 28 05 ?? ?? ?? ?? 8B 08 A1 ?? ?? ?? ?? 0F 11 45 ?? }
        $s2 = { C7 45 ?? 1B 12 1F 04 } 

    condition:
        filesize < 230KB and all of them
}
