(function () {
  var KEY = 'pg-theme';
  var btn = document.getElementById('themeToggle');
  var label = document.getElementById('themeToggleLabel');
  if (!btn) return;

  function current() {
    return document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light';
  }

  function render() {
    var dark = current() === 'dark';
    var action = dark ? 'Switch to light mode' : 'Switch to dark mode';
    btn.setAttribute('aria-pressed', String(dark));
    btn.setAttribute('aria-label', action);
    btn.title = action;
    if (label) label.textContent = dark ? 'Dark mode' : 'Light mode';
  }

  function apply(theme, persist) {
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
    if (persist) {
      try { localStorage.setItem(KEY, theme); } catch (e) { /* storage unavailable */ }
    }
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', theme === 'dark' ? '#080e1a' : '#f3f6fb');
    render();
  }

  btn.addEventListener('click', function () {
    apply(current() === 'dark' ? 'light' : 'dark', true);
  });

  window.addEventListener('storage', function (event) {
    if (event.key !== KEY) return;
    if (event.newValue === 'dark' || event.newValue === 'light') {
      apply(event.newValue, false);
    }
  });

  render();
})();
