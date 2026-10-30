use chrono::{DateTime, Datelike, FixedOffset, NaiveDate, TimeZone, Utc};
use std::collections::BTreeSet;

struct CronSchedule {
    minutes: BTreeSet<u32>,
    hours: BTreeSet<u32>,
    days_of_month: BTreeSet<u32>,
    months: BTreeSet<u32>,
    days_of_week: BTreeSet<u32>,
    day_of_month_is_any: bool,
    day_of_week_is_any: bool,
}

fn field_value(value: &str, names: &[(&str, u32)], maximum: u32) -> Result<u32, String> {
    if let Some((_, number)) = names
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(value))
    {
        return Ok(*number);
    }
    let number = value
        .parse::<u32>()
        .map_err(|_| format!("Invalid cron value '{value}'."))?;
    if number > maximum {
        return Err(format!("Cron value '{value}' is out of range."));
    }
    Ok(number)
}

fn parse_field(
    field: &str,
    minimum: u32,
    maximum: u32,
    names: &[(&str, u32)],
    sunday_alias: bool,
) -> Result<(BTreeSet<u32>, bool), String> {
    let mut values = BTreeSet::new();
    let mut is_any = false;
    for item in field.split(',') {
        if item.is_empty() {
            return Err("Cron fields cannot contain empty list entries.".into());
        }
        let (range, step) = match item.split_once('/') {
            Some((range, step)) if !step.is_empty() && !range.is_empty() => {
                let step = step
                    .parse::<u32>()
                    .map_err(|_| "Cron step values must be positive integers.".to_owned())?;
                if step == 0 {
                    return Err("Cron step values must be positive integers.".into());
                }
                (range, Some(step))
            }
            Some(_) => return Err("Cron step values must be positive integers.".into()),
            None => (item, None),
        };
        let (start, end) = if range == "*" {
            is_any = true;
            (minimum, maximum)
        } else if let Some((start, end)) = range.split_once('-') {
            let start = field_value(start, names, maximum)?;
            let end = field_value(end, names, maximum)?;
            if start < minimum || end < minimum || start > end {
                return Err("Cron ranges must stay within the field and ascend.".into());
            }
            (start, end)
        } else {
            let start = field_value(range, names, maximum)?;
            if start < minimum {
                return Err("Cron value is below the field's minimum.".into());
            }
            (start, if step.is_some() { maximum } else { start })
        };
        for value in (start..=end).step_by(step.unwrap_or(1) as usize) {
            values.insert(if sunday_alias && value == 7 { 0 } else { value });
        }
    }
    Ok((values, is_any))
}

fn parse(expression: &str) -> Result<CronSchedule, String> {
    if expression.len() > 128 {
        return Err("Cron expression must be at most 128 characters.".into());
    }
    let fields: Vec<_> = expression.split_whitespace().collect();
    if fields.len() != 5 {
        return Err("Use five cron fields: minute hour day-of-month month day-of-week.".into());
    }
    let month_names = [
        ("JAN", 1),
        ("FEB", 2),
        ("MAR", 3),
        ("APR", 4),
        ("MAY", 5),
        ("JUN", 6),
        ("JUL", 7),
        ("AUG", 8),
        ("SEP", 9),
        ("OCT", 10),
        ("NOV", 11),
        ("DEC", 12),
    ];
    let weekday_names = [
        ("SUN", 0),
        ("MON", 1),
        ("TUE", 2),
        ("WED", 3),
        ("THU", 4),
        ("FRI", 5),
        ("SAT", 6),
    ];
    let (minutes, _) = parse_field(fields[0], 0, 59, &[], false)?;
    let (hours, _) = parse_field(fields[1], 0, 23, &[], false)?;
    let (days_of_month, day_of_month_is_any) = parse_field(fields[2], 1, 31, &[], false)?;
    let (months, _) = parse_field(fields[3], 1, 12, &month_names, false)?;
    let (days_of_week, day_of_week_is_any) = parse_field(fields[4], 0, 7, &weekday_names, true)?;
    Ok(CronSchedule {
        minutes,
        hours,
        days_of_month,
        months,
        days_of_week,
        day_of_month_is_any,
        day_of_week_is_any,
    })
}

pub(crate) fn validate(expression: &str) -> Result<(), String> {
    parse(expression).map(|_| ())
}

fn matches_day(schedule: &CronSchedule, date: NaiveDate) -> bool {
    if !schedule.months.contains(&date.month()) {
        return false;
    }
    let day_of_month_matches = schedule.days_of_month.contains(&date.day());
    let day_of_week = date.weekday().num_days_from_sunday();
    let day_of_week_matches = schedule.days_of_week.contains(&day_of_week);
    match (schedule.day_of_month_is_any, schedule.day_of_week_is_any) {
        (true, true) => true,
        (true, false) => day_of_week_matches,
        (false, true) => day_of_month_matches,
        // Standard cron runs on either day when both day fields are restricted.
        (false, false) => day_of_month_matches || day_of_week_matches,
    }
}

pub(crate) fn next_after(expression: &str, now: DateTime<Utc>) -> Result<DateTime<Utc>, String> {
    let schedule = parse(expression)?;
    let hong_kong = FixedOffset::east_opt(8 * 60 * 60).expect("UTC+8 is a valid offset");
    let local_now = now.with_timezone(&hong_kong);
    let local_naive = local_now.naive_local();

    // Search a full Gregorian calendar cycle so leap-day and weekday schedules
    // always find their next occurrence if the expression can match.
    for offset in 0..=(366 * 400) {
        let date = local_now.date_naive() + chrono::Duration::days(offset);
        if !matches_day(&schedule, date) {
            continue;
        }
        for hour in &schedule.hours {
            for minute in &schedule.minutes {
                let Some(candidate) = date.and_hms_opt(*hour, *minute, 0) else {
                    continue;
                };
                if candidate <= local_naive {
                    continue;
                }
                if let Some(candidate) = hong_kong.from_local_datetime(&candidate).single() {
                    return Ok(candidate.with_timezone(&Utc));
                }
            }
        }
    }
    Err("This cron expression has no upcoming scheduled time.".into())
}

pub(crate) fn expression(profile: &serde_json::Value) -> String {
    if let Some(expression) = profile["cron_expression"]
        .as_str()
        .filter(|expression| !expression.trim().is_empty())
    {
        return expression.trim().to_owned();
    }

    let weekday = match profile["schedule_weekday"].as_str().unwrap_or("mon") {
        "sun" => "0",
        "mon" => "1",
        "tue" => "2",
        "wed" => "3",
        "thu" => "4",
        "fri" => "5",
        "sat" => "6",
        value => value,
    };
    let (hour, minute) = profile["schedule_time"]
        .as_str()
        .unwrap_or("09:00")
        .split_once(':')
        .unwrap_or(("09", "00"));
    format!("{minute} {hour} * * {weekday}")
}
