# Journal entries

`journey.html` renders every file listed in `index.json`, a JSON array of file
names relative to this folder. Each file holds one entry object, or an array of
entry objects. Entries are shown newest first.

## Entry schema

| Field      | Type       | Notes |
|------------|------------|-------|
| `title`    | string     | Required. Shown as the entry heading and in the title filter. |
| `date`     | string     | `YYYY-MM-DD`. Drives the date filter and the sort order. |
| `tldr`     | string     | One-line summary shown under the title. |
| `contents` | string[]   | Each item is rendered as its own markdown block: paragraph, heading, list, fenced code, quote or table. |
| `tags`     | string[]   | Shown as chips. Clicking a chip searches for that tag. |
| `id`       | string     | Optional anchor for `journey.html#id`. Defaults to the file name without `.json`. |

## Adding an entry

1. Create `YYYY-MM-DD-short-title.json` in this folder.
2. Add the file name to `index.json`.

Entries are fetched over HTTP, so preview the site through a web server
(for example `python3 -m http.server`) rather than a `file://` URL.
