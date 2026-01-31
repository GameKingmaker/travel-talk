/* =========================
   Toast (알림)
========================= */
function showToast(message) {
  const prev = document.querySelector(".toast-msg");
  if (prev) prev.remove();

  const el = document.createElement("div");
  el.className = "toast-msg";
  el.textContent = message;
  document.body.appendChild(el);

  requestAnimationFrame(() => el.classList.add("show"));

  setTimeout(() => {
    el.classList.remove("show");
    setTimeout(() => el.remove(), 250);
  }, 1600);
}

/* =========================
   Speech (TTS)
========================= */
function speak(text) {
  if (!text) return;

  const synth = window.speechSynthesis;
  if (!synth) {
    alert("이 브라우저는 음성 재생을 지원하지 않아요.");
    return;
  }

  synth.cancel();
  const u = new SpeechSynthesisUtterance(text);
  u.lang = "ja-JP";
  u.rate = 0.95;
  u.pitch = 1.0;
  synth.speak(u);
}

function initSpeakButtons() {
  document.addEventListener("click", (e) => {
    const btn = e.target.closest(".speak-btn, .tts-btn");
    if (!btn) return;

    // ✅ data-tts가 tojson 형태일 수도 있으니 안전 파싱
    const raw = btn.getAttribute("data-tts") || btn.dataset.tts || "";
    const text = parseMaybeJSON(raw);

    speak(text);
  });
}

/* =========================
   Utils
========================= */
function safeParseJSON(raw, fallback = {}) {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

// ✅ dataset 값이 '"안녕"' 처럼 JSON 문자열일 수 있어서 처리
function parseMaybeJSON(raw) {
  if (raw == null) return "";
  const s = String(raw).trim();
  if (!s) return "";

  // JSON 문자열/객체/배열 형태면 파싱
  if (
    (s.startsWith('"') && s.endsWith('"')) ||
    (s.startsWith("{") && s.endsWith("}")) ||
    (s.startsWith("[") && s.endsWith("]"))
  ) {
    try {
      const v = JSON.parse(s);
      // 문자열이면 그대로
      if (typeof v === "string") return v;
      // 객체면 string으로 못 쓰니 안전하게 빈값
      return "";
    } catch {
      return s;
    }
  }
  return s;
}

function localTogglePhrase(key, payload, nextOn) {
  const storeKey = "fav_phrases_v1";
  const raw = localStorage.getItem(storeKey);
  let obj = safeParseJSON(raw, {});

  if (typeof obj !== "object" || obj === null || Array.isArray(obj)) obj = {};

  if (nextOn) obj[key] = payload;
  else delete obj[key];

  localStorage.setItem(storeKey, JSON.stringify(obj));
}

/* =========================
   상황별 회화 즐겨찾기 (/api/favorites)
   - 버튼: .fav-btn (phrase-card 안)
   - 상태: classList 'on' 으로 판단
========================= */
async function togglePhraseFavorite(cardEl, btnEl) {
  if (!window.IS_LOGGED_IN) {
    showToast("로그인이 필요합니다.");
    return;
  }

  const key = cardEl.dataset.key || "";

  // ✅ 템플릿에서 data-jp/pron/ko를 tojson으로 넣었을 때도 안전하게 복원
  const jp = parseMaybeJSON(cardEl.getAttribute("data-jp") || cardEl.dataset.jp || "");
  const pron = parseMaybeJSON(cardEl.getAttribute("data-pron") || cardEl.dataset.pron || "");
  const ko = parseMaybeJSON(cardEl.getAttribute("data-ko") || cardEl.dataset.ko || "");

  const isOn = btnEl.classList.contains("on");
  const nextOn = !isOn;

  // UI 먼저 반영
  btnEl.classList.toggle("on", nextOn);

  const payload = {
    action: nextOn ? "add" : "remove",
    phrase_key: key,
    jp,
    pron,
    ko,
  };

  try {
    const res = await fetch("/api/favorites", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    // 로그인 필요
    if (res.status === 401) {
      // 롤백
      btnEl.classList.toggle("on", isOn);
      showToast("로그인이 필요합니다.");
      return;
    }

    if (!res.ok) {
      // 실패하면 UI 롤백
      btnEl.classList.toggle("on", isOn);
      showToast("저장에 실패했어요.");
      return;
    }

    showToast(nextOn ? "나만의 학습노트에 저장되었습니다." : "학습노트에서 제거되었습니다.");
  } catch (err) {
    // 네트워크 실패: 로컬 저장 (비로그인 지원하려면 여기에서 막지 않도록 정책 조정 가능)
    localTogglePhrase(key, { jp, pron, ko }, nextOn);
    showToast(nextOn ? "나만의 학습노트에 저장되었습니다." : "학습노트에서 제거되었습니다.");
  }
}

function initPhraseFavButtons() {
  document.addEventListener("click", (e) => {
    const btn = e.target.closest(".fav-btn");
    if (!btn) return;

    // 단어 페이지의 fav-btn도 같은 클래스라서 구분 필요:
    // 단어 버튼은 data-cat / data-jp 를 가지고 있음
    if (btn.dataset && btn.dataset.cat && btn.dataset.jp) return;

    const card = btn.closest(".phrase-card");
    if (!card) return;

    togglePhraseFavorite(card, btn);
  });
}

/* =========================
   단어 즐겨찾기 (/api/word_fav)
   - 버튼: .fav-btn (words_detail.html 테이블/리스트 안)
========================= */
async function toggleWordFavorite(btn) {
  const cat_key = btn.dataset.cat;
  const jp = btn.dataset.jp;

  if (!cat_key || !jp) return;

  const isOn = btn.classList.contains("on");
  const nextOn = !isOn;

  // UI 먼저 반영
  btn.classList.toggle("on", nextOn);
  btn.textContent = nextOn ? "★" : "☆";

  const action = nextOn ? "add" : "remove";

  try {
    const res = await fetch("/api/word_fav", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cat_key, jp, action }),
    });

    if (res.status === 401) {
      // 롤백
      btn.classList.toggle("on", isOn);
      btn.textContent = isOn ? "★" : "☆";
      showToast("로그인이 필요합니다.");
      return;
    }

    const data = await res.json().catch(() => ({}));
    if (!data.ok) {
      // 롤백
      btn.classList.toggle("on", isOn);
      btn.textContent = isOn ? "★" : "☆";
      showToast(data.error || "저장에 실패했어요.");
      return;
    }

    showToast(nextOn ? "나만의 학습노트에 저장되었습니다." : "학습노트에서 제거되었습니다.");
  } catch (e) {
    // 롤백
    btn.classList.toggle("on", isOn);
    btn.textContent = isOn ? "★" : "☆";
    showToast("네트워크 오류로 실패했어요.");
  }
}

function initWordFavButtons() {
  document.addEventListener("click", (e) => {
    const btn = e.target.closest(".fav-btn");
    if (!btn) return;

    // 단어 버튼만 처리: data-cat, data-jp 있어야 함
    if (!(btn.dataset && btn.dataset.cat && btn.dataset.jp)) return;

    toggleWordFavorite(btn);
  });
}

/* =========================
   Register Live Validation (기존 그대로)
========================= */
function setMsg(el, text, kind) {
  if (!el) return;
  el.textContent = text || "";
  el.classList.remove("ok", "bad");
  if (kind === "ok") el.classList.add("ok");
  if (kind === "bad") el.classList.add("bad");
}

function debounce(fn, delay = 300) {
  let t = null;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), delay);
  };
}

function initRegisterValidation() {
  const form = document.querySelector("#register-form");
  if (!form) return;

  const $u = document.querySelector("#reg-username");
  const $p = document.querySelector("#reg-password");
  const $p2 = document.querySelector("#reg-password2");
  const $n = document.querySelector("#reg-nickname");
  const $e = document.querySelector("#reg-email");
  const $e2 = document.querySelector("#reg-email2");

  const mu = document.querySelector("#msg-username");
  const mp = document.querySelector("#msg-password");
  const mp2 = document.querySelector("#msg-password2");
  const mn = document.querySelector("#msg-nickname");
  const me = document.querySelector("#msg-email");
  const me2 = document.querySelector("#msg-email2");

  const usernameRe = /^[A-Za-z][A-Za-z0-9]{2,19}$/;

  const checkUsername = debounce(async () => {
    const v = ($u.value || "").trim();
    if (!v) return setMsg(mu, "", null);

    if (!usernameRe.test(v)) {
      return setMsg(mu, "이 아이디는 사용할 수 없습니다. (영문 시작/영문+숫자 3~20자)", "bad");
    }

    setMsg(mu, "형식 확인 중...", null);
    try {
      const res = await fetch(`/api/validate/username?u=${encodeURIComponent(v)}`);
      const data = await res.json();
      if (data.ok) setMsg(mu, data.msg, "ok");
      else setMsg(mu, data.msg, "bad");
    } catch {
      setMsg(mu, "확인 실패(네트워크). 잠시 후 다시 시도해주세요.", "bad");
    }
  }, 250);

  const checkPassword = () => {
    const v = $p.value || "";
    if (!v) return setMsg(mp, "", null);

    if (v.length < 8 || v.length > 16) {
      return setMsg(mp, "이 비밀번호는 사용할 수 없습니다. (8~16자)", "bad");
    }
    setMsg(mp, "사용 가능한 비밀번호입니다.", "ok");
  };

  const checkPassword2 = () => {
    const v = $p.value || "";
    const v2 = $p2.value || "";
    if (!v2) return setMsg(mp2, "", null);
    if (v2 !== v) return setMsg(mp2, "비밀번호가 일치하지 않습니다.", "bad");
    setMsg(mp2, "비밀번호가 일치합니다.", "ok");
  };

  const checkNickname = debounce(async () => {
    const v = ($n.value || "").trim();
    if (!v) return setMsg(mn, "", null);

    if (v.length < 2 || v.length > 8) {
      return setMsg(mn, "이 닉네임은 사용할 수 없습니다. (2~8자)", "bad");
    }

    setMsg(mn, "형식 확인 중...", null);
    try {
      const res = await fetch(`/api/validate/nickname?n=${encodeURIComponent(v)}`);
      const data = await res.json();
      if (data.ok) setMsg(mn, data.msg, "ok");
      else setMsg(mn, data.msg, "bad");
    } catch {
      setMsg(mn, "확인 실패(네트워크). 잠시 후 다시 시도해주세요.", "bad");
    }
  }, 250);

  const checkEmail = debounce(async () => {
    const v = ($e.value || "").trim().toLowerCase();
    if (!v) return setMsg(me, "", null);

    setMsg(me, "형식 확인 중...", null);
    try {
      const res = await fetch(`/api/validate/email?e=${encodeURIComponent(v)}`);
      const data = await res.json();
      if (data.ok) setMsg(me, data.msg, "ok");
      else setMsg(me, data.msg, "bad");
    } catch {
      setMsg(me, "확인 실패(네트워크). 잠시 후 다시 시도해주세요.", "bad");
    }
  }, 250);

  const checkEmail2 = () => {
    const v = ($e.value || "").trim().toLowerCase();
    const v2 = ($e2.value || "").trim().toLowerCase();
    if (!v2) return setMsg(me2, "", null);
    if (v !== v2) return setMsg(me2, "이메일이 서로 일치하지 않습니다.", "bad");
    setMsg(me2, "이메일이 일치합니다.", "ok");
  };

  $u.addEventListener("input", checkUsername);
  $p.addEventListener("input", () => {
    checkPassword();
    checkPassword2();
  });
  $p2.addEventListener("input", checkPassword2);
  $n.addEventListener("input", checkNickname);
  $e.addEventListener("input", () => {
    checkEmail();
    checkEmail2();
  });
  $e2.addEventListener("input", checkEmail2);

  if ($u.value) checkUsername();
  if ($n.value) checkNickname();
  if ($e.value) checkEmail();
  if ($e2.value) checkEmail2();
}

/* =========================
   Note Page (기존 로직 유지 + 안정화)
========================= */
function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function initNotePage() {
  const noteList = document.querySelector("#noteList");   // 문장
  const wordList = document.querySelector("#wordList");   // 단어
  if (!noteList && !wordList) return;

  const togglePron = document.querySelector("#toggle-pron");
  const toggleKo = document.querySelector("#toggle-ko");

  function applyHide() {
    const hidePron = !!(togglePron && togglePron.checked);
    const hideKo   = !!(toggleKo && toggleKo.checked);

    if (noteList) {
      noteList.classList.toggle("hide-pron", hidePron);
      noteList.classList.toggle("hide-ko", hideKo);
    }
    if (wordList) {
      wordList.classList.toggle("hide-pron", hidePron);
      wordList.classList.toggle("hide-ko", hideKo);
    }
  }

  if (togglePron) togglePron.addEventListener("change", applyHide);
  if (toggleKo) toggleKo.addEventListener("change", applyHide);
  applyHide();

  const isLoggedIn = document.body.dataset.loggedIn === "1";
  if (isLoggedIn) return;

  const storeKey = "fav_phrases_v1";
  const raw = localStorage.getItem(storeKey);

  let obj = safeParseJSON(raw, {});
  if (typeof obj !== "object" || obj === null || Array.isArray(obj)) {
    localStorage.removeItem(storeKey);
    obj = {};
  }

  const keys = Object.keys(obj);

  if (keys.length === 0) {
    if (noteList) {
      noteList.innerHTML = `<div class="empty">이 브라우저에 저장된 즐겨찾기가 없습니다. ⭐로 저장해보세요.</div>`;
    }
    return;
  }

  if (!noteList) return;

  noteList.innerHTML = keys
    .map((k) => {
      const it = obj[k] || {};
      const jp = it.jp || "";
      const pron = it.pron || "";
      const ko = it.ko || "";
      return `
      <div class="phrase-card" data-key="${escapeHtml(k)}"
           data-jp="${escapeHtml(jp)}" data-pron="${escapeHtml(pron)}" data-ko="${escapeHtml(ko)}">
        <button class="fav-btn on" type="button" title="즐겨찾기 해제">★</button>
        <div class="phrase-body">
          <div class="p-line"><span class="p-label">일본어:</span> <span class="p-jp">${escapeHtml(jp)}</span></div>
          <div class="p-line"><span class="p-label">발음:</span> <span class="p-pron">${escapeHtml(pron)}</span></div>
          <div class="p-line"><span class="p-label">뜻:</span> <span class="p-ko">${escapeHtml(ko)}</span></div>
        </div>
        <button class="speak-btn" type="button" data-tts="${escapeHtml(jp)}">발음 듣기</button>
      </div>
    `;
    })
    .join("");
}

/* =========================
   Boot
========================= */
document.addEventListener("DOMContentLoaded", () => {
  try {
    initNotePage();
  } catch (e) {
    console.error("[note] init failed", e);
  }

  initSpeakButtons();
  initPhraseFavButtons();
  initWordFavButtons();
  initRegisterValidation();
});
// ✅ 로그인/회원가입 새창(팝업) 방지: 항상 현재 창에서 열기
document.addEventListener("click", function (e) {
  const a = e.target.closest('a[href]');
  if (!a) return;

  const href = a.getAttribute("href") || "";

  // 로그인/회원가입 링크만 대상으로 잡기
  if (href.includes("/login") || href.includes("/register")) {
    // 혹시 target이나 window.open 로직이 있어도 막고 현재 창 이동
    e.preventDefault();
    window.location.href = href;
  }
}, true); // ← 캡처링 단계에서 먼저 가로채기
