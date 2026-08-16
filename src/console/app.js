/* shinu console — no frameworks, no build step.
   One script drives both pages; <body data-page="auth|console"> picks the path.
   Every string interpolated into HTML goes through esc(): space names, notes,
   emails and tokens are all user-controlled. */
'use strict';
(function () {
  /* ================= shared helpers ================= */

  function $(selector, root) {
    return (root || document).querySelector(selector);
  }

  function esc(value) {
    return String(value == null ? '' : value).replace(/[&<>"']/g, function (ch) {
      return {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
      }[ch];
    });
  }

  function ApiError(message, status) {
    Error.call(this, message);
    this.message = message;
    this.status = status;
  }
  ApiError.prototype = Object.create(Error.prototype);

  /* All console traffic goes through here. credentials:'same-origin' is what
     carries the shinu_session cookie the browser got at login. */
  function api(method, path, body) {
    return fetch(path, {
      method: method,
      credentials: 'same-origin',
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    }).then(null, function () {
      throw new ApiError('cannot reach the shinu daemon', 0);
    }).then(function (res) {
      return res.text().then(function (text) {
        var data = null;
        if (text) {
          try {
            data = JSON.parse(text);
          } catch (_) {
            /* error bodies are always JSON; a non-JSON 2xx is treated as empty */
          }
        }
        if (!res.ok) {
          var message =
            data && typeof data.error === 'string'
              ? data.error
              : 'request failed (HTTP ' + res.status + ')';
          throw new ApiError(message, res.status);
        }
        return data;
      });
    });
  }

  function shortId(id) {
    return id ? String(id).slice(0, 8) : null;
  }

  function fmtBytes(n) {
    n = Number(n) || 0;
    if (n < 1024) return n + ' B';
    var units = ['KiB', 'MiB', 'GiB', 'TiB'];
    var v = n;
    var u = -1;
    while (v >= 1024 && u < units.length - 1) {
      v /= 1024;
      u += 1;
    }
    return (v >= 100 ? Math.round(v) : v.toFixed(1)) + ' ' + units[u];
  }

  function fmtMib(mib) {
    return fmtBytes((Number(mib) || 0) * 1024 * 1024);
  }

  function fmtDuration(totalSeconds) {
    var s = Math.max(0, Number(totalSeconds) || 0);
    if (s < 60) return s + ' s';
    if (s < 3600) return Math.round(s / 60) + ' min';
    var h = s / 3600;
    return (h >= 10 ? Math.round(h) : h.toFixed(1)) + ' h';
  }

  function timeAgo(iso) {
    var t = new Date(iso);
    if (isNaN(t.getTime())) return String(iso || '');
    var s = Math.floor((Date.now() - t.getTime()) / 1000);
    if (s < 5) return 'just now';
    if (s < 60) return s + ' s ago';
    var m = Math.floor(s / 60);
    if (m < 60) return m + ' min ago';
    var h = Math.floor(m / 60);
    if (h < 24) return h + ' h ago';
    var d = Math.floor(h / 24);
    if (d < 30) return d + ' d ago';
    return t.toISOString().slice(0, 10);
  }

  function absTime(iso) {
    var t = new Date(iso);
    return isNaN(t.getTime()) ? String(iso || '') : t.toLocaleString();
  }

  /* ================= notices ================= */

  function notify(kind, message) {
    var area = $('#notice-area');
    if (!area) return;
    var sig = kind + ':' + message;
    for (var i = 0; i < area.children.length; i += 1) {
      if (area.children[i].getAttribute('data-sig') === sig) return;
    }
    var div = document.createElement('div');
    div.className = 'notice ' + kind;
    div.setAttribute('data-sig', sig);
    var span = document.createElement('span');
    span.className = 'notice-msg';
    span.textContent = message;
    var close = document.createElement('button');
    close.type = 'button';
    close.className = 'notice-close';
    close.setAttribute('aria-label', 'Dismiss');
    close.textContent = '×';
    close.addEventListener('click', function () {
      div.remove();
    });
    div.appendChild(span);
    div.appendChild(close);
    area.appendChild(div);
    if (kind !== 'error') {
      setTimeout(function () {
        if (div.isConnected) div.remove();
      }, 8000);
    }
  }

  /* ================= modal ================= */

  /* opts: { title, bodyHTML, actions: [{ label, kind, disabled, onClick(btn, close) }] }.
     An action without onClick just closes. Used instead of window.confirm so the
     destructive step can carry real context (what is deleted, what is archived). */
  function openModal(opts) {
    var root = $('#modal-root');
    if (!root) return function () {};
    root.innerHTML =
      '<div class="modal-overlay"><div class="modal" role="dialog" aria-modal="true" aria-label="' +
      esc(opts.title) +
      '"><div class="modal-head">' +
      esc(opts.title) +
      '</div><div class="modal-body">' +
      opts.bodyHTML +
      '</div><div class="modal-foot"></div></div></div>';
    root.hidden = false;
    var overlay = root.firstElementChild;
    var foot = root.querySelector('.modal-foot');

    function close() {
      root.hidden = true;
      root.innerHTML = '';
      document.removeEventListener('keydown', onKey);
    }

    opts.actions.forEach(function (action) {
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'btn' + (action.kind ? ' ' + action.kind : '');
      btn.textContent = action.label;
      if (action.disabled) btn.disabled = true;
      btn.addEventListener('click', function () {
        if (action.onClick) action.onClick(btn, close);
        else close();
      });
      foot.appendChild(btn);
    });

    overlay.addEventListener('mousedown', function (ev) {
      if (ev.target === overlay) close();
    });
    function onKey(ev) {
      if (ev.key === 'Escape') close();
    }
    document.addEventListener('keydown', onKey);

    var focusTarget =
      root.querySelector('input') || foot.querySelector('.btn');
    if (focusTarget) focusTarget.focus();
    return close;
  }

  /* ================= auth page ================= */

  function initAuth() {
    var form = $('#auth-form');
    var email = $('#email');
    var password = $('#password');
    var hint = $('#password-hint');
    var errBox = $('#form-error');
    var submit = $('#submit-btn');
    var tabs = { login: $('#tab-login'), register: $('#tab-register') };
    var mode = /register/.test(location.pathname) ? 'register' : 'login';

    function showError(message) {
      errBox.textContent = message;
      errBox.hidden = false;
    }

    function setMode(next) {
      mode = next;
      var registering = mode === 'register';
      Object.keys(tabs).forEach(function (key) {
        var active = key === mode;
        tabs[key].classList.toggle('active', active);
        tabs[key].setAttribute('aria-selected', String(active));
      });
      submit.textContent = registering ? 'Create account' : 'Log in';
      password.setAttribute(
        'autocomplete',
        registering ? 'new-password' : 'current-password'
      );
      hint.hidden = !registering;
      errBox.hidden = true;
      document.title = registering ? 'shinu — register' : 'shinu — log in';
      /* Keep the URL in sync so a refresh keeps the mode. The History API
         throws on file:// previews, hence the protocol guard. */
      if (location.protocol.indexOf('http') === 0) {
        history.replaceState(null, '', registering ? '/register' : '/login');
      }
    }

    tabs.login.addEventListener('click', function () {
      setMode('login');
    });
    tabs.register.addEventListener('click', function () {
      setMode('register');
    });
    setMode(mode);

    /* Already signed in → straight to the console. A 401 means "stay";
       a network failure means the daemon is down — say so instead of
       leaving the page silently broken (also covers file:// previews). */
    api('GET', '/console/me').then(
      function () {
        if (location.protocol.indexOf('http') === 0) location.replace('/app');
      },
      function (err) {
        if (err.status === 0) {
          showError('Cannot reach the shinu daemon — is it running?');
        }
      }
    );

    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      errBox.hidden = true;
      var address = email.value.trim();
      var secret = password.value;
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(address)) {
        showError('Enter a valid email address.');
        email.focus();
        return;
      }
      if (!secret) {
        showError('Enter your password.');
        password.focus();
        return;
      }
      /* The backend enforces the same minimum; checking here saves a round trip. */
      if (mode === 'register' && secret.length < 12) {
        showError('Password must be at least 12 characters.');
        password.focus();
        return;
      }
      submit.disabled = true;
      submit.textContent =
        mode === 'register' ? 'Creating account…' : 'Logging in…';
      api('POST', '/console/' + mode, { email: address, password: secret }).then(
        function () {
          if (location.protocol.indexOf('http') === 0) location.replace('/app');
        },
        function (err) {
          /* Login failures deliberately don't reveal whether the email or the
             password was wrong — show the server's wording verbatim. */
          showError(err.message);
          submit.disabled = false;
          submit.textContent = mode === 'register' ? 'Create account' : 'Log in';
        }
      );
    });
  }

  /* ================= console page ================= */

  function initConsole() {
    var state = {
      me: null,
      spaces: null, /* null = never loaded; poll errors keep stale data */
      limits: null,
      usage: null,
      tokens: null,
      selected: null,
      tab: 'log',
      log: null,
      reflog: null,
      historyError: null,
      actionBusy: false,
    };
    var spacesCacheKey = '';
    var headCacheKey = '';

    /* Console-flavoured api(): an expired session (401) anywhere sends the
       browser back to the login page. */
    function capi(method, path, body) {
      return api(method, path, body).then(null, function (err) {
        if (err.status === 401 && location.protocol.indexOf('http') === 0) {
          location.replace('/login');
        }
        throw err;
      });
    }

    function selectedSpace() {
      if (!state.selected || !state.spaces) return null;
      for (var i = 0; i < state.spaces.length; i += 1) {
        if (state.spaces[i].name === state.selected) return state.spaces[i];
      }
      return null;
    }

    function errorState(message, retryAction) {
      return (
        '<div class="state error"><p>' +
        esc(message) +
        '</p><button class="btn small" type="button" data-action="' +
        retryAction +
        '">Retry</button></div>'
      );
    }

    /* ---------- rendering ---------- */

    function renderSpaces() {
      if (!state.spaces) return;
      var key = JSON.stringify(state.spaces) + '|' + state.selected;
      if (key === spacesCacheKey) return; /* poll with no changes: keep the DOM */
      spacesCacheKey = key;
      var list = $('#spaces-list');
      if (state.spaces.length === 0) {
        list.innerHTML =
          '<div class="state"><p>No spaces yet.</p>' +
          '<p class="muted">Create one above to start experimenting.</p></div>';
        return;
      }
      list.innerHTML =
        '<table class="data-table"><thead><tr><th>Name</th><th>State</th>' +
        '<th>HEAD</th><th>Disk</th></tr></thead><tbody>' +
        state.spaces
          .map(function (s) {
            return (
              '<tr class="space-row' +
              (s.name === state.selected ? ' selected' : '') +
              '" data-action="select-space" data-name="' +
              esc(s.name) +
              '" title="created ' +
              esc(absTime(s.created_at)) +
              /* the name cell carries a real button so the row stays
                 keyboard-operable; closest('[data-action]') finds it first */
              '"><td><button type="button" class="rowlink" data-action="select-space" data-name="' +
              esc(s.name) +
              '">' +
              esc(s.name) +
              '</button></td><td>' +
              (s.running ? '<span class="green">running</span>' : 'stopped') +
              '</td><td class="mono">' +
              (s.head ? esc(shortId(s.head)) : '&mdash;') +
              '</td><td class="mono nobr">' +
              esc(fmtBytes(s.exclusive || 0)) +
              '</td></tr>'
            );
          })
          .join('') +
        '</tbody></table>';
    }

    function renderDetailHead(force) {
      var s = selectedSpace();
      if (!s) return;
      if (state.actionBusy && !force) return;
      var key = s.name + '|' + s.running + '|' + (s.head || '');
      if (!force && key === headCacheKey) return;
      headCacheKey = key;
      $('#detail-title').textContent = s.name;
      $('#detail-actions').innerHTML =
        (s.running
          ? '<button class="btn small" type="button" data-action="stop-space">Stop</button>'
          : '<button class="btn small primary" type="button" data-action="start-space">Start</button>') +
        '<button class="btn small danger" type="button" data-action="delete-space">Delete</button>';
      $('#commit-hint').textContent = s.running
        ? 'Space is running — a commit must be hot, or stop the space first.'
        : 'Saves a checkpoint of the current disk and moves HEAD to it.';
    }

    function renderDetail() {
      var s = selectedSpace();
      $('#detail-empty').hidden = !!s;
      $('#detail-main').hidden = !s;
      if (s) {
        renderDetailHead(true);
        renderCommitList();
      }
    }

    function renderCommitList() {
      var s = selectedSpace();
      if (!s) return;
      $('#tab-hint').textContent =
        state.tab === 'log'
          ? 'Ancestor chain from HEAD — the story of this space.'
          : 'Every checkpoint of this space, automatic ones included.';
      var list = $('#commit-list');
      if (state.historyError) {
        list.innerHTML = errorState(state.historyError, 'retry-history');
        return;
      }
      var rows = state.tab === 'log' ? state.log : state.reflog;
      if (!rows) {
        list.innerHTML =
          '<div class="state"><span class="spin"></span>Loading&hellip;</div>';
        return;
      }
      if (rows.length === 0) {
        list.innerHTML =
          state.tab === 'log'
            ? '<div class="state"><p>No commits yet.</p>' +
              '<p class="muted">Commit above to create the first save point.</p></div>'
            : '<div class="state"><p>The archive is empty.</p></div>';
        return;
      }
      list.innerHTML =
        '<table class="data-table"><thead><tr><th>Id</th><th>When</th>' +
        '<th>Note</th><th>Actions</th></tr></thead><tbody>' +
        rows
          .map(function (c) {
            var badges = '';
            if (c.id === s.head) badges += ' <span class="badge head">HEAD</span>';
            if (c.auto) badges += ' <span class="badge auto">auto</span>';
            return (
              '<tr class="commit-row"><td class="commit-id mono nobr" title="' +
              esc(c.id) +
              '">' +
              esc(shortId(c.id)) +
              badges +
              '</td><td class="commit-time nobr" title="' +
              esc(absTime(c.created_at)) +
              '">' +
              esc(timeAgo(c.created_at)) +
              '</td><td class="commit-note">' +
              esc(c.note || '') +
              '</td><td><div class="row-actions">' +
              '<button class="btn small" type="button" data-action="checkout-commit" data-id="' +
              esc(c.id) +
              '">Check out</button>' +
              '<button class="btn small" type="button" data-action="fork-commit" data-id="' +
              esc(c.id) +
              '">Fork</button></div></td></tr>'
            );
          })
          .join('') +
        '</tbody></table>';
    }

    /* One quota row: label, "used / limit" as text (red near the cap), and a
       hard-edged bar — solid fill, square corners, no animation. */
    function meterRow(label, used, max, fmt) {
      used = Number(used) || 0;
      max = Number(max) || 0;
      var pct =
        max > 0 ? Math.min(100, Math.round((used / max) * 100)) : used > 0 ? 100 : 0;
      var cls = pct >= 100 ? ' full' : pct >= 80 ? ' warn' : '';
      return (
        '<tr><td>' +
        esc(label) +
        '</td><td class="mono nobr' +
        (pct >= 80 ? ' red' : '') +
        '">' +
        esc(fmt(used)) +
        ' / ' +
        esc(fmt(max)) +
        '</td><td class="quota-bar-cell"><div class="meter' +
        cls +
        '"><div class="fill" style="width:' +
        pct +
        '%"></div></div></td></tr>'
      );
    }

    function renderQuota() {
      var L = state.limits;
      if (!L) return;
      $('#meters').innerHTML =
        '<table class="data-table quota-table"><thead><tr><th>Resource</th>' +
        '<th>Used / limit</th><th>Usage</th></tr></thead><tbody>' +
        meterRow('Spaces', L.used.spaces, L.max_spaces, String) +
        meterRow('Disk', L.used.disk_mib, L.max_disk_mib, fmtMib) +
        meterRow('Running VMs', L.used.running, L.max_running, String) +
        '<tr><td>API rate</td><td class="mono nobr">' +
        esc(String(L.api_per_min)) +
        ' / min</td><td class="muted">per-minute request limit</td></tr>' +
        '</tbody></table>';
      var U = state.usage;
      if (U) {
        $('#usage-line').textContent =
          'All time: ' +
          U.spaces_created +
          ' spaces created · ' +
          fmtDuration(U.vm_seconds) +
          ' VM time · ' +
          fmtMib(U.disk_mib_hour) +
          '·h disk · ' +
          U.api_calls +
          ' API calls';
      }
    }

    function renderTokens() {
      if (!state.tokens) return;
      var list = $('#tokens-list');
      if (state.tokens.length === 0) {
        list.innerHTML =
          '<div class="state"><p>No tokens yet.</p>' +
          '<p class="muted">Create one to use the CLI or an MCP client.</p></div>';
        return;
      }
      list.innerHTML =
        '<table class="data-table"><thead><tr><th>Prefix</th><th>Created</th>' +
        '<th>Actions</th></tr></thead><tbody>' +
        state.tokens
          .map(function (t) {
            return (
              '<tr class="token-row"><td class="token-prefix mono" title="token hash prefix">' +
              esc(t.hash_prefix) +
              '</td><td class="token-created" title="' +
              esc(absTime(t.created_at)) +
              '">created ' +
              esc(timeAgo(t.created_at)) +
              '</td><td><button class="btn small danger" type="button" data-action="revoke-token" data-prefix="' +
              esc(t.hash_prefix) +
              '">Revoke</button></td></tr>'
            );
          })
          .join('') +
        '</tbody></table>';
    }

    /* ---------- data loading ---------- */

    function refreshSpaces(quiet) {
      return capi('GET', '/v1/spaces').then(
        function (data) {
          state.spaces = (data && data.spaces) || [];
          if (
            state.selected &&
            !state.spaces.some(function (sp) {
              return sp.name === state.selected;
            })
          ) {
            /* deleted elsewhere (another tab, the CLI) — drop the detail view */
            state.selected = null;
            state.log = state.reflog = null;
            renderDetail();
          }
          renderSpaces();
          renderDetailHead(false);
        },
        function (err) {
          if (quiet && state.spaces) {
            notify('error', err.message);
            return;
          }
          $('#spaces-list').innerHTML = errorState(err.message, 'retry-spaces');
        }
      );
    }

    function refreshQuota(quiet) {
      return Promise.all([capi('GET', '/v1/limits'), capi('GET', '/v1/usage')]).then(
        function (results) {
          state.limits = results[0];
          state.usage = results[1];
          renderQuota();
        },
        function (err) {
          if (quiet && state.limits) {
            notify('error', err.message);
            return;
          }
          $('#meters').innerHTML = errorState(err.message, 'retry-quota');
        }
      );
    }

    function refreshTokens(quiet) {
      return capi('GET', '/console/tokens').then(
        function (data) {
          state.tokens = (data && data.tokens) || [];
          renderTokens();
        },
        function (err) {
          if (quiet && state.tokens) {
            notify('error', err.message);
            return;
          }
          $('#tokens-list').innerHTML = errorState(err.message, 'retry-tokens');
        }
      );
    }

    function loadHistory(which) {
      var name = state.selected;
      if (!name) return Promise.resolve();
      return capi(
        'GET',
        '/v1/spaces/' + encodeURIComponent(name) + '/' + which
      ).then(
        function (data) {
          if (state.selected !== name) return;
          if (which === 'log') state.log = (data && data.commits) || [];
          else state.reflog = (data && data.entries) || [];
          state.historyError = null;
          if (which === state.tab) renderCommitList();
        },
        function (err) {
          if (state.selected !== name || which !== state.tab) return;
          state.historyError = err.message;
          renderCommitList();
        }
      );
    }

    function refreshAll() {
      refreshSpaces(false);
      refreshQuota(false);
      refreshTokens(false);
      if (state.selected) loadHistory(state.tab);
    }

    /* ---------- interactions ---------- */

    /* ---------- view switching (sidemenu) ----------
       The four panels are views: exactly one is visible at a time. Purely
       presentational — all data loading/polling runs regardless of which
       view is shown. */

    var views = {
      spaces: $('#spaces-panel'),
      commits: $('#detail-panel'),
      tokens: $('#tokens-panel'),
      quota: $('#quota-panel'),
    };
    var menuItems = document.querySelectorAll('.menu-item');

    function setView(name) {
      if (!views[name]) return;
      Object.keys(views).forEach(function (key) {
        views[key].hidden = key !== name;
      });
      for (var i = 0; i < menuItems.length; i += 1) {
        var active = menuItems[i].getAttribute('data-view') === name;
        menuItems[i].classList.toggle('active', active);
        menuItems[i].setAttribute('aria-pressed', String(active));
      }
    }

    function selectSpace(name) {
      if (!name || name === state.selected) return;
      state.selected = name;
      state.tab = 'log';
      /* the commit form belongs to the previous space otherwise */
      $('#commit-note').value = '';
      $('#commit-hot').checked = false;
      $('#commit-error').hidden = true;
      state.log = state.reflog = null;
      state.historyError = null;
      $('#tab-log').classList.add('active');
      $('#tab-log').setAttribute('aria-selected', 'true');
      $('#tab-reflog').classList.remove('active');
      $('#tab-reflog').setAttribute('aria-selected', 'false');
      renderSpaces();
      renderDetail();
      /* selecting a space jumps to its save points, mirroring the old
         side-by-side layout where the detail appeared on selection */
      setView('commits');
      loadHistory('log');
    }

    function setTab(tab) {
      if (state.tab === tab) return;
      state.tab = tab;
      state.historyError = null;
      $('#tab-log').classList.toggle('active', tab === 'log');
      $('#tab-log').setAttribute('aria-selected', String(tab === 'log'));
      $('#tab-reflog').classList.toggle('active', tab === 'reflog');
      $('#tab-reflog').setAttribute('aria-selected', String(tab === 'reflog'));
      renderCommitList();
      if (tab === 'log' && !state.log) loadHistory('log');
      if (tab === 'reflog' && !state.reflog) loadHistory('reflog');
    }

    function setRunning(start) {
      var s = selectedSpace();
      if (!s || state.actionBusy) return;
      state.actionBusy = true;
      var buttons = $('#detail-actions').querySelectorAll('button');
      for (var i = 0; i < buttons.length; i += 1) buttons[i].disabled = true;
      capi(
        'POST',
        '/v1/spaces/' + encodeURIComponent(s.name) + (start ? '/start' : '/stop')
      ).then(
        function () {
          notify('ok', 'Space ' + s.name + (start ? ' started.' : ' stopped.'));
          refreshSpaces(true);
          refreshQuota(true);
        },
        function (err) {
          notify('error', err.message);
        }
      ).then(function () {
        state.actionBusy = false;
        renderDetailHead(true);
      });
    }

    function askDeleteSpace() {
      var s = selectedSpace();
      if (!s) return;
      openModal({
        title: 'Delete space',
        bodyHTML:
          '<p>Delete space <strong>' +
          esc(s.name) +
          '</strong>?</p><p>The space is stopped and its working disk is removed. ' +
          'Archived checkpoints are kept. This cannot be undone.</p>',
        actions: [
          { label: 'Cancel' },
          {
            label: 'Delete space',
            kind: 'danger',
            onClick: function (btn, close) {
              btn.disabled = true;
              capi('DELETE', '/v1/spaces/' + encodeURIComponent(s.name)).then(
                function () {
                  close();
                  notify('ok', 'Space ' + s.name + ' deleted.');
                  if (state.selected === s.name) {
                    state.selected = null;
                    state.log = state.reflog = null;
                    renderDetail();
                  }
                  refreshSpaces(true);
                  refreshQuota(true);
                },
                function (err) {
                  close();
                  notify('error', err.message);
                }
              );
            },
          },
        ],
      });
    }

    function askCheckout(commitId) {
      var s = selectedSpace();
      if (!s) return;
      var short = shortId(commitId);
      openModal({
        title: 'Check out ' + short,
        bodyHTML:
          '<p>Space <strong>' +
          esc(s.name) +
          '</strong> switches to save point <span class="mono">' +
          esc(short) +
          '</span>.</p><p>The current state is archived automatically as an ' +
          '<em>auto</em> checkpoint first — you can come back to it at any time. ' +
          'Nothing is discarded.</p>' +
          (s.running
            ? '<p class="modal-warn">The space is running — stop it before checking out.</p>'
            : ''),
        actions: [
          { label: 'Cancel' },
          {
            label: 'Check out',
            kind: 'primary',
            disabled: s.running,
            onClick: function (btn, close) {
              btn.disabled = true;
              capi('POST', '/v1/spaces/' + encodeURIComponent(s.name) + '/checkout', {
                commit: commitId,
              }).then(
                function (result) {
                  close();
                  var archived =
                    result && result.auto_commit
                      ? '; previous state archived as ' + shortId(result.auto_commit)
                      : '';
                  notify('ok', 'Checked out ' + short + archived + '.');
                  state.log = state.reflog = null;
                  refreshSpaces(true);
                  loadHistory(state.tab);
                  renderCommitList();
                  refreshQuota(true);
                },
                function (err) {
                  close();
                  notify('error', err.message);
                }
              );
            },
          },
        ],
      });
    }

    function askFork(commitId) {
      var s = selectedSpace();
      if (!s) return;
      var short = shortId(commitId);
      openModal({
        title: 'Fork ' + short,
        bodyHTML:
          '<p>Create a new space starting from save point <span class="mono">' +
          esc(short) +
          '</span>.</p><label class="field"><span>New space name</span>' +
          '<input type="text" id="fork-name" autocomplete="off" placeholder="e.g. ' +
          esc(s.name) +
          '-experiment"></label>' +
          '<p class="form-error" id="fork-error" hidden></p>',
        actions: [
          { label: 'Cancel' },
          {
            label: 'Fork',
            kind: 'primary',
            onClick: function (btn, close) {
              var input = $('#fork-name');
              var errBox = $('#fork-error');
              var name = input.value.trim();
              if (!name) {
                errBox.textContent = 'Name the new space.';
                errBox.hidden = false;
                input.focus();
                return;
              }
              btn.disabled = true;
              capi('POST', '/v1/commits/' + encodeURIComponent(commitId) + '/fork', {
                name: name,
              }).then(
                function () {
                  close();
                  notify('ok', 'Space ' + name + ' forked from ' + short + '.');
                  /* quota errors surface inline below instead */
                  refreshSpaces(true).then(function () {
                    selectSpace(name);
                  });
                  refreshQuota(true);
                },
                function (err) {
                  /* stays inside the modal: name conflicts and quota errors
                     are fixable by editing the input */
                  btn.disabled = false;
                  errBox.textContent = err.message;
                  errBox.hidden = false;
                }
              );
            },
          },
        ],
      });
    }

    function askRevokeToken(prefix) {
      openModal({
        title: 'Revoke token',
        bodyHTML:
          '<p>Revoke token <span class="mono">' +
          esc(prefix) +
          '</span>?</p><p>Any client authenticating with it loses access ' +
          'immediately. This cannot be undone.</p>',
        actions: [
          { label: 'Cancel' },
          {
            label: 'Revoke',
            kind: 'danger',
            onClick: function (btn, close) {
              btn.disabled = true;
              capi('DELETE', '/console/tokens/' + encodeURIComponent(prefix)).then(
                function () {
                  close();
                  notify('ok', 'Token ' + prefix + ' revoked.');
                  refreshTokens(true);
                },
                function (err) {
                  close();
                  notify('error', err.message);
                }
              );
            },
          },
        ],
      });
    }

    function onCreateSpace(ev) {
      ev.preventDefault();
      var input = $('#create-name');
      var errBox = $('#create-error');
      var btn = $('#create-btn');
      errBox.hidden = true;
      var name = input.value.trim();
      if (!name) {
        errBox.textContent = 'Name the space first.';
        errBox.hidden = false;
        input.focus();
        return;
      }
      btn.disabled = true;
      capi('POST', '/v1/spaces', { name: name }).then(
        function () {
          input.value = '';
          notify('ok', 'Space ' + name + ' created.');
          refreshSpaces(true).then(function () {
            selectSpace(name);
          });
          refreshQuota(true);
        },
        function (err) {
          /* 429 quota errors arrive pre-written for users — show as-is. */
          errBox.textContent = err.message;
          errBox.hidden = false;
        }
      ).then(function () {
        btn.disabled = false;
      });
    }

    function onCommit(ev) {
      ev.preventDefault();
      var s = selectedSpace();
      if (!s) return;
      var errBox = $('#commit-error');
      var noteInput = $('#commit-note');
      var hotBox = $('#commit-hot');
      var btn = $('#commit-btn');
      errBox.hidden = true;
      var note = noteInput.value.trim();
      var hot = hotBox.checked;
      if (!note) {
        errBox.textContent = 'A note is required — describe what changed.';
        errBox.hidden = false;
        noteInput.focus();
        return;
      }
      if (s.running && !hot) {
        errBox.textContent = 'The space is running: check "hot" or stop it first.';
        errBox.hidden = false;
        return;
      }
      btn.disabled = true;
      capi('POST', '/v1/spaces/' + encodeURIComponent(s.name) + '/commits', {
        note: note,
        hot: hot,
      }).then(
        function () {
          noteInput.value = '';
          hotBox.checked = false;
          notify('ok', 'Checkpoint saved.');
          state.log = state.reflog = null;
          refreshSpaces(true);
          loadHistory(state.tab);
          renderCommitList();
          refreshQuota(true);
        },
        function (err) {
          errBox.textContent = err.message;
          errBox.hidden = false;
        }
      ).then(function () {
        btn.disabled = false;
      });
    }

    function onNewToken() {
      var btn = $('#new-token-btn');
      btn.disabled = true;
      capi('POST', '/console/tokens', {}).then(
        function (data) {
          if (data && data.token) {
            $('#token-value').textContent = data.token;
            $('#token-reveal').hidden = false;
            $('#copy-token-btn').textContent = 'Copy';
          }
          refreshTokens(true);
        },
        function (err) {
          notify('error', err.message);
        }
      ).then(function () {
        btn.disabled = false;
      });
    }

    function onCopyToken() {
      var btn = $('#copy-token-btn');
      var token = $('#token-value').textContent;
      function done(ok) {
        btn.textContent = ok ? 'Copied' : 'Copy failed — select the text manually';
        setTimeout(function () {
          btn.textContent = 'Copy';
        }, 1600);
      }
      /* The async Clipboard API needs a secure context; plain http installs
         fall back to selection-copy. */
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(token).then(
          function () {
            done(true);
          },
          function () {
            legacyCopy();
          }
        );
      } else {
        legacyCopy();
      }
      function legacyCopy() {
        var ta = document.createElement('textarea');
        ta.value = token;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        var ok = false;
        try {
          ok = document.execCommand('copy');
        } catch (_) {
          ok = false;
        }
        ta.remove();
        done(ok);
      }
    }

    function onLogout() {
      /* Even if the request fails, leaving is the right move: the me-check on
         the login page bounces back only if the session is genuinely alive. */
      capi('POST', '/console/logout').then(
        function () {},
        function () {}
      ).then(function () {
        if (location.protocol.indexOf('http') === 0) location.replace('/login');
      });
    }

    var actions = {
      'select-space': function (el) {
        selectSpace(el.getAttribute('data-name'));
      },
      'start-space': function () {
        setRunning(true);
      },
      'stop-space': function () {
        setRunning(false);
      },
      'delete-space': askDeleteSpace,
      'checkout-commit': function (el) {
        askCheckout(el.getAttribute('data-id'));
      },
      'fork-commit': function (el) {
        askFork(el.getAttribute('data-id'));
      },
      'revoke-token': function (el) {
        askRevokeToken(el.getAttribute('data-prefix'));
      },
      'retry-spaces': function () {
        $('#spaces-list').innerHTML =
          '<div class="state"><span class="spin"></span>Loading&hellip;</div>';
        refreshSpaces(false);
      },
      'retry-quota': function () {
        $('#meters').innerHTML =
          '<div class="state"><span class="spin"></span>Loading&hellip;</div>';
        refreshQuota(false);
      },
      'retry-tokens': function () {
        $('#tokens-list').innerHTML =
          '<div class="state"><span class="spin"></span>Loading&hellip;</div>';
        refreshTokens(false);
      },
      'retry-history': function () {
        state.historyError = null;
        if (state.tab === 'log') state.log = null;
        else state.reflog = null;
        renderCommitList();
        loadHistory(state.tab);
      },
      'retry-boot': function () {
        location.reload();
      },
    };

    document.addEventListener('click', function (ev) {
      var el = ev.target.closest('[data-action]');
      if (!el) return;
      var run = actions[el.getAttribute('data-action')];
      if (run) run(el);
    });

    for (var mi = 0; mi < menuItems.length; mi += 1) {
      menuItems[mi].addEventListener('click', function () {
        setView(this.getAttribute('data-view'));
      });
    }

    $('#refresh-btn').addEventListener('click', refreshAll);
    $('#logout-btn').addEventListener('click', onLogout);
    $('#create-form').addEventListener('submit', onCreateSpace);
    $('#commit-form').addEventListener('submit', onCommit);
    $('#tab-log').addEventListener('click', function () {
      setTab('log');
    });
    $('#tab-reflog').addEventListener('click', function () {
      setTab('reflog');
    });
    $('#new-token-btn').addEventListener('click', onNewToken);
    $('#copy-token-btn').addEventListener('click', onCopyToken);
    $('#dismiss-token-btn').addEventListener('click', function () {
      $('#token-reveal').hidden = true;
      $('#token-value').textContent = '';
    });

    /* ---------- boot ---------- */

    capi('GET', '/console/me').then(
      function (me) {
        state.me = me || {};
        $('#user-email').textContent = state.me.email || '';
        $('#project-badge').textContent = state.me.project || '';
        if (state.me.project) {
          document.title = 'shinu console — ' + state.me.project;
        }
        refreshAll();
        setInterval(function () {
          if (document.hidden) return;
          refreshSpaces(true);
          refreshQuota(true);
        }, 5000);
      },
      function (err) {
        /* 401 already redirected inside capi. Anything else (daemon down,
           file:// preview) gets an explicit, retryable failure state. */
        if (err.status === 401) return;
        notify('error', err.message);
        $('#spaces-list').innerHTML = errorState(err.message, 'retry-boot');
        $('#meters').innerHTML = errorState(err.message, 'retry-boot');
        $('#tokens-list').innerHTML = errorState(err.message, 'retry-boot');
      }
    );
  }

  /* ================= dispatch ================= */

  var page = document.body ? document.body.getAttribute('data-page') : null;
  try {
    if (page === 'auth') initAuth();
    else if (page === 'console') initConsole();
  } catch (err) {
    /* Last-resort feedback: never leave a silent white page. */
    var div = document.createElement('div');
    div.className = 'notice error';
    div.textContent =
      'console UI failed to initialise: ' + (err && err.message ? err.message : err);
    document.body.prepend(div);
  }
})();
