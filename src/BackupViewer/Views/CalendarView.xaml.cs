using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using BackupViewer.Models;
using BackupViewer.Services;

namespace BackupViewer.Views;

public partial class CalendarView : UserControl
{
    private IReadOnlyList<CalendarInfo> _calendars = [];
    private IReadOnlyList<CalendarEventItem> _events = [];
    private DateTime _month;
    private DateTime? _selectedDay;
    private long? _calendarFilter;
    private string _search = "";
    private readonly CultureInfo _it = CultureInfo.GetCultureInfo("it-IT");

    public CalendarView()
    {
        InitializeComponent();
        _month = new DateTime(DateTime.Today.Year, DateTime.Today.Month, 1);
        BuildDayHeaders();
    }

    public void Bind(CoreDataService core)
    {
        _calendars = core.Snapshot.Calendars;
        _events = core.Snapshot.Events;
        var all = new CalendarInfo { Id = -1, Title = "Tutti i calendari", EventCount = _events.Count };
        var items = new List<CalendarInfo> { all };
        items.AddRange(_calendars);
        CalendarList.ItemsSource = items;
        CalendarList.SelectedIndex = 0;
        _selectedDay = DateTime.Today;
        RenderMonth();
        RefreshDayEvents();
    }

    public void ApplySearch(string query)
    {
        _search = query ?? "";
        RefreshDayEvents();
    }

    private void BuildDayHeaders()
    {
        DayHeaders.Children.Clear();
        var names = _it.DateTimeFormat.AbbreviatedDayNames;
        // Monday-first
        for (var i = 1; i <= 7; i++)
        {
            var idx = i % 7;
            DayHeaders.Children.Add(new TextBlock
            {
                Text = names[idx].ToUpperInvariant(),
                HorizontalAlignment = HorizontalAlignment.Center,
                FontSize = 11,
                FontWeight = FontWeights.SemiBold,
                Foreground = (Brush)FindResource("MutedBrush"),
                Margin = new Thickness(0, 0, 0, 4),
            });
        }
    }

    private void CalendarList_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (CalendarList.SelectedItem is not CalendarInfo cal)
            return;
        _calendarFilter = cal.Id < 0 ? null : cal.Id;
        RenderMonth();
        RefreshDayEvents();
    }

    private void PrevMonth_OnClick(object sender, RoutedEventArgs e)
    {
        _month = _month.AddMonths(-1);
        RenderMonth();
    }

    private void NextMonth_OnClick(object sender, RoutedEventArgs e)
    {
        _month = _month.AddMonths(1);
        RenderMonth();
    }

    private void Today_OnClick(object sender, RoutedEventArgs e)
    {
        _month = new DateTime(DateTime.Today.Year, DateTime.Today.Month, 1);
        _selectedDay = DateTime.Today;
        RenderMonth();
        RefreshDayEvents();
    }

    private void RenderMonth()
    {
        MonthLabel.Text = _month.ToString("MMMM yyyy", _it);
        DayGrid.Children.Clear();

        var first = _month;
        var offset = ((int)first.DayOfWeek + 6) % 7; // Monday=0
        var daysInMonth = DateTime.DaysInMonth(_month.Year, _month.Month);
        var eventDays = FilteredEvents()
            .Where(static e => e.Start is not null)
            .Select(static e => e.Start!.Value.ToLocalTime().Date)
            .ToHashSet();

        for (var cell = 0; cell < 42; cell++)
        {
            var dayNum = cell - offset + 1;
            Border cellBorder;
            if (dayNum < 1 || dayNum > daysInMonth)
            {
                cellBorder = new Border { Background = Brushes.Transparent };
            }
            else
            {
                var date = new DateTime(_month.Year, _month.Month, dayNum);
                var hasEvents = eventDays.Contains(date.Date);
                var isSelected = _selectedDay?.Date == date.Date;
                var isToday = date.Date == DateTime.Today;

                var btn = new Button
                {
                    Content = BuildDayContent(dayNum, hasEvents, isToday),
                    Tag = date,
                    Cursor = System.Windows.Input.Cursors.Hand,
                    Background = isSelected
                        ? (Brush)FindResource("AccentSoftBrush")
                        : Brushes.Transparent,
                    BorderBrush = isToday
                        ? (Brush)FindResource("AccentBrush")
                        : Brushes.Transparent,
                    BorderThickness = new Thickness(isToday ? 1.5 : 0),
                    Padding = new Thickness(2),
                    Margin = new Thickness(2),
                };
                btn.Click += Day_OnClick;
                cellBorder = new Border { Child = btn };
            }

            DayGrid.Children.Add(cellBorder);
        }
    }

    private static UIElement BuildDayContent(int day, bool hasEvents, bool isToday)
    {
        var panel = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center };
        panel.Children.Add(new TextBlock
        {
            Text = day.ToString(CultureInfo.InvariantCulture),
            HorizontalAlignment = HorizontalAlignment.Center,
            FontWeight = isToday ? FontWeights.Bold : FontWeights.Normal,
            FontSize = 13,
        });
        if (hasEvents)
        {
            panel.Children.Add(new Ellipse
            {
                Width = 5,
                Height = 5,
                Margin = new Thickness(0, 2, 0, 0),
                Fill = new SolidColorBrush(Color.FromRgb(0x0F, 0x76, 0x6E)),
                HorizontalAlignment = HorizontalAlignment.Center,
            });
        }

        return panel;
    }

    private void Day_OnClick(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: DateTime date })
            return;
        _selectedDay = date;
        RenderMonth();
        RefreshDayEvents();
    }

    private void RefreshDayEvents()
    {
        var day = _selectedDay?.Date;
        DayHeader.Text = day is null
            ? "EVENTI"
            : $"EVENTI · {day.Value.ToString("ddd dd MMM", _it)}";

        var list = FilteredEvents()
            .Where(e => day is null || (e.Start?.ToLocalTime().Date == day))
            .OrderBy(static e => e.Start ?? DateTimeOffset.MaxValue)
            .ToList();
        EventList.ItemsSource = list;
        if (list.Count > 0)
            EventList.SelectedIndex = 0;
        else
            ClearDetail();
    }

    private IEnumerable<CalendarEventItem> FilteredEvents()
    {
        IEnumerable<CalendarEventItem> q = _events;
        if (_calendarFilter is long id)
            q = q.Where(e => e.CalendarId == id);
        if (!string.IsNullOrWhiteSpace(_search))
        {
            q = q.Where(e =>
                e.Summary.Contains(_search, StringComparison.OrdinalIgnoreCase)
                || (e.Location?.Contains(_search, StringComparison.OrdinalIgnoreCase) ?? false)
                || (e.Description?.Contains(_search, StringComparison.OrdinalIgnoreCase) ?? false)
                || e.CalendarTitle.Contains(_search, StringComparison.OrdinalIgnoreCase));
        }

        return q;
    }

    private void EventList_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (EventList.SelectedItem is not CalendarEventItem ev)
        {
            ClearDetail();
            return;
        }

        DetailTitle.Text = ev.Summary;
        DetailWhen.Text = ev.WhenLabel + (ev.AllDay ? " (tutto il giorno)" : "")
                          + " · " + ev.CalendarTitle;
        DetailLoc.Text = string.IsNullOrWhiteSpace(ev.Location) ? "" : ev.Location;
        DetailDesc.Text = ev.Description ?? ev.Url ?? "";
    }

    private void ClearDetail()
    {
        DetailTitle.Text = "";
        DetailWhen.Text = "";
        DetailLoc.Text = "";
        DetailDesc.Text = "";
    }
}
