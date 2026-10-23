"""Five-field cron schedules ("m h dom mon dow"), evaluated in a timezone.

Supports *, lists (1,15), ranges (1-5), steps (*/10, 0-30/5) and the
shortcuts @hourly, @daily, @weekly and @monthly. Like cron, when both the
day of month and the day of week are restricted, either one matching is
enough. Day of week 0 and 7 are both Sunday.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

MACROS = {
    "@hourly": "0 * * * *",
    "@daily": "0 0 * * *",
    "@midnight": "0 0 * * *",
    "@weekly": "0 0 * * 0",
    "@monthly": "0 0 1 * *",
}
FIELDS = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))


class CronError(ValueError):
    pass


@dataclass(frozen=True)
class Schedule:
    minutes: frozenset[int]
    hours: frozenset[int]
    days: frozenset[int]
    months: frozenset[int]
    weekdays: frozenset[int]  # 0 = Sunday
    any_day: bool
    any_weekday: bool

    def _day_matches(self, moment: datetime) -> bool:
        weekday = (moment.weekday() + 1) % 7
        if self.any_day and self.any_weekday:
            return True
        if self.any_day:
            return weekday in self.weekdays
        if self.any_weekday:
            return moment.day in self.days
        return moment.day in self.days or weekday in self.weekdays

    def next_after(self, after: datetime, tz: str = "UTC") -> datetime:
        """The first matching minute strictly after `after` (returned in UTC)."""
        zone = timezone(tz)
        moment = after.astimezone(zone).replace(second=0, microsecond=0)
        moment += timedelta(minutes=1)
        limit = moment + timedelta(days=366 * 5)
        while moment < limit:
            if moment.month not in self.months:
                year = moment.year + (moment.month == 12)
                month = moment.month % 12 + 1
                moment = moment.replace(year=year, month=month, day=1, hour=0, minute=0)
                continue
            if not self._day_matches(moment):
                moment = (moment + timedelta(days=1)).replace(hour=0, minute=0)
                continue
            if moment.hour not in self.hours:
                moment = (moment + timedelta(hours=1)).replace(minute=0)
                continue
            if moment.minute not in self.minutes:
                moment += timedelta(minutes=1)
                continue
            return moment.astimezone(UTC)
        raise CronError("This schedule never runs")


def timezone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        raise CronError(f"Unknown timezone: {name}") from None


def _field(text: str, low: int, high: int) -> frozenset[int]:
    values: set[int] = set()
    for part in text.split(","):
        base, _, step_text = part.partition("/")
        step = 1
        if step_text:
            if not step_text.isdigit() or int(step_text) < 1:
                raise CronError(f"Bad step in '{part}'")
            step = int(step_text)
        if base == "*":
            start, end = low, high
        elif "-" in base:
            a, _, b = base.partition("-")
            if not (a.isdigit() and b.isdigit()):
                raise CronError(f"Bad range '{base}'")
            start, end = int(a), int(b)
        elif base.isdigit():
            start = int(base)
            end = high if step_text else start
        else:
            raise CronError(f"'{part}' isn't a number, range or *")
        if not low <= start <= end <= high:
            raise CronError(f"'{part}' is outside {low}-{high}")
        values.update(range(start, end + 1, step))
    return frozenset(values)


def parse(expression: str) -> Schedule:
    text = MACROS.get(expression.strip().lower(), expression.strip())
    parts = text.split()
    if len(parts) != 5:
        raise CronError("A schedule has five fields: minute hour day month weekday")
    fields = [_field(p, *bounds) for p, bounds in zip(parts, FIELDS, strict=True)]
    weekdays = frozenset(0 if d == 7 else d for d in fields[4])
    return Schedule(
        minutes=fields[0],
        hours=fields[1],
        days=fields[2],
        months=fields[3],
        weekdays=weekdays,
        any_day=parts[2] == "*",
        any_weekday=parts[4] == "*",
    )
