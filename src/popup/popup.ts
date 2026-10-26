// ANP wallet popup — create → unlock → wallet list → wallet detail (key mgmt) → sign.
import { generateMnemonicPhrase } from '../lib/anp'
import type { StoredAccount, Wallet, StoredKey, ActiveKeyRef, PendingRequest } from '../protocol'
import { BgRequest, BgResponse } from '../protocol'

function $(id: string): HTMLElement {
  const el = document.getElementById(id)
  if (!el) throw new Error(`missing #${id}`)
  return el
}

async function send<T = BgResponse>(msg: BgRequest): Promise<T> {
  return (await chrome.runtime.sendMessage(msg)) as T
}

function setVisible(id: string, on: boolean) {
  $(id).classList.toggle('hidden', !on)
}

type View = 'create' | 'addwallet' | 'unlock' | 'register' | 'home' | 'wallet' | 'sign'
const VIEWS: View[] = ['create', 'addwallet', 'unlock', 'register', 'home', 'wallet', 'sign']
const AUTO_ROUTE: View[] = ['create', 'unlock', 'home', 'sign']

function showView(view: View) {
  for (const v of VIEWS) setVisible(`view-${v}`, v === view)
}

interface State {
  status: string
  unlocked: boolean
  account: StoredAccount | null
  activeRef: ActiveKeyRef | null
  pending: PendingRequest[]
}

// Manual-entry views that survive re-render (back-navigation goes via render()).
let detailWalletId: string | null = null
let regWalletId: string | null = null

const short = (s: string, n = 18) => (s.length > n ? s.slice(0, n) + '…' : s)
const localOf = (handle: string, fallback: string) => handle.split('.')[0] || fallback

async function render() {
  const state = await send<State>({ type: 'anp-wallet/get-state' })
  const account = state.account
  const unlocked = state.unlocked
  const pending = state.pending
  const activeRef = state.activeRef

  const header = document.querySelector('header') as HTMLElement
  header.classList.toggle('unlocked', unlocked)
  const pill = $('lock-pill')
  pill.textContent = unlocked ? '已解锁' : '已锁定'
  pill.classList.toggle('unlocked', unlocked)
  pill.classList.toggle('locked', !unlocked)

  // 打开时路由：没账户(或空账户)→创建；有账户但锁定→解锁；已解锁→签名(有请求)/注册(手动)/钱包详情(手动)/列表。
  let view: View
  if (!account || account.wallets.length === 0) view = 'create'
  else if (!unlocked) view = 'unlock'
  else if (pending.length > 0) view = 'sign'
  else if (regWalletId) view = 'register'
  else if (detailWalletId) view = 'wallet'
  else view = 'home'
  showView(view)

  if (account) {
    if (view === 'home') renderWalletList(account, activeRef)
    else if (view === 'wallet') renderWalletDetail(account, detailWalletId ? walletById(account, detailWalletId) : null, activeRef)
  }
  if (view === 'sign') renderSignList(pending, unlocked, account, activeRef)
}

function currentWallet(account: StoredAccount | null, activeRef: ActiveKeyRef | null): Wallet | null {
  if (!account || account.wallets.length === 0) return null
  const id = activeRef?.walletId || account.activeWalletId
  return walletById(account, id) ?? account.wallets[0]
}

function walletById(account: StoredAccount, id: string | null): Wallet | null {
  if (!id) return null
  return account.wallets.find((w) => w.id === id) ?? account.wallets[0] ?? null
}

function isActive(activeRef: ActiveKeyRef | null, walletId: string, keyIndex: number) {
  return Boolean(activeRef && activeRef.walletId === walletId && activeRef.keyIndex === keyIndex)
}

// ---------------------------------------------------------------------------
// Wallet list (home)
// ---------------------------------------------------------------------------
function renderWalletList(account: StoredAccount, activeRef: ActiveKeyRef | null) {
  const list = $('wallet-list')
  list.textContent = ''
  for (const w of account.wallets) {
    const card = document.createElement('li')
    card.className = 'wallet-card'
    card.style.listStyle = 'none'

    const top = document.createElement('div')
    top.className = 'wc-top'
    const label = document.createElement('div')
    label.className = 'wc-label'
    label.textContent = w.label
    top.appendChild(label)
    const chevron = document.createElement('span')
    chevron.className = 'chevron'
    chevron.textContent = '›'
    top.appendChild(chevron)
    card.appendChild(top)

    const handle = document.createElement('div')
    handle.className = 'wc-handle'
    handle.textContent = w.handle ? `handle ${w.handle}` : '尚未绑定 handle'
    card.appendChild(handle)
    if (w.keys.length > 0) {
      const primary = w.keys[w.primaryKeyIndex]
      const sub = document.createElement('div')
      sub.className = 'wc-sub'
      if (primary) {
        const pid = document.createElement('span')
        pid.className = 'wc-primary'
        pid.textContent = `主 ${short(primary.did, 30)}`
        sub.appendChild(pid)
      }
      const status = document.createElement('span')
      status.className = 'pill'
      status.textContent = `${w.keys.length} 密钥`
      sub.appendChild(status)
      card.appendChild(sub)
    }

    card.addEventListener('click', () => goDetail(w.id))
    list.appendChild(card)
  }
}

// ---------------------------------------------------------------------------
// Wallet detail: header + key list
// ---------------------------------------------------------------------------
function renderWalletDetail(account: StoredAccount, wallet: Wallet | null, activeRef: ActiveKeyRef | null) {
  const list = $('key-list')
  if (!wallet) {
    list.textContent = ''
    $('wallet-label').textContent = ''
    $('wallet-handle').textContent = ''
    $('wallet-pill').textContent = ''
    detailWalletId = null
    return
  }

  $('wallet-label').textContent = wallet.label
  $('wallet-handle').textContent = wallet.handle
    ? `handle ${wallet.handle}`
    : '尚未绑定 handle（在下方点「注册」）'

  const primaryPill = $('wallet-primary')
  const pri = wallet.keys[wallet.primaryKeyIndex]
  primaryPill.textContent = pri ? `主 key#${pri.index}` : '主'
  primaryPill.classList.toggle('hidden', !pri)

  const pill = $('wallet-pill')
  pill.textContent = `${wallet.keys.length} 密钥`
  pill.className = 'pill'

  // Registration is a capability, not a status — always offer it.
  const regBtn = $('btn-wallet-register')
  regBtn.classList.remove('hidden')

  // Key list.
  list.textContent = ''
  if (wallet.keys.length === 0) {
    const empty = document.createElement('li')
    empty.className = 'empty'
    empty.textContent = '尚无密钥，点「＋ 添加密钥」派生第一把 DID。'
    list.appendChild(empty)
  } else {
    wallet.keys.forEach((key, keyIndex) => list.appendChild(renderKey(wallet, key, keyIndex, activeRef)))
  }

  // Every wallet is deletable, even the last one.
  $('btn-wallet-delete').classList.remove('hidden')
}

function renderKey(wallet: Wallet, key: StoredKey, keyIndex: number, activeRef: ActiveKeyRef | null): HTMLLIElement {
  const li = document.createElement('li')
  li.className = 'key'

  const head = document.createElement('div')
  head.className = 'khead'
  const kid = document.createElement('span')
  kid.className = 'kid'
  kid.textContent = short(key.keyid || key.did || `key#${key.index}`, 40)
  head.appendChild(kid)
  if (keyIndex === wallet.primaryKeyIndex) {
    const p = document.createElement('span')
    p.className = 'pill primary'
    p.textContent = '主'
    head.appendChild(p)
  }
  if (isActive(activeRef, wallet.id, keyIndex)) {
    const d = document.createElement('span')
    d.className = 'pill default'
    d.textContent = '默认'
    head.appendChild(d)
  }
  li.appendChild(head)

  const khandle = document.createElement('div')
  khandle.className = 'khandle'
  khandle.textContent = `handle ${key.handle || '（未注册）'}`
  li.appendChild(khandle)

  const isPrimary = keyIndex === wallet.primaryKeyIndex
  const isDefault = isActive(activeRef, wallet.id, keyIndex)
  const kactions = document.createElement('div')
  kactions.className = 'kactions'

  if (!isPrimary) {
    kactions.appendChild(
      btn('设为主', async () => {
        const resp = await send<{ status: string; error?: string }>({ type: 'anp-wallet/set-primary', walletId: wallet.id, keyIndex })
        if (resp.status !== 'ok') alert(resp.error ?? '设置主密钥失败')
        await render()
      }),
    )
  }
  if (!isDefault) {
    kactions.appendChild(btn('设为默认', () => withDelayedRender(send({ type: 'anp-wallet/select-active', walletId: wallet.id, keyIndex }))))
  }
  if (wallet.keys.length > 1 && !isPrimary) {
    kactions.appendChild(
      confirmBtn('删除', async () => {
        await send({ type: 'anp-wallet/delete-key', walletId: wallet.id, keyIndex })
        await render()
      }),
    )
  }

  li.appendChild(kactions)
  return li
}

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------
function goDetail(walletId: string) {
  detailWalletId = walletId
  regWalletId = null
  void render()
}

function goHome() {
  detailWalletId = null
  void render()
}

function goRegister(walletId: string) {
  regWalletId = walletId
  void (async () => {
    const state = await send<State>({ type: 'anp-wallet/get-state' })
    const account = state.account
    if (!account) return
    const wallet = walletById(account, walletId)
    if (!wallet) return
    const pri = wallet.keys[wallet.primaryKeyIndex]
    $('reg-primary-did').textContent = pri ? short(pri.did, 44) : '（无密钥，先添加密钥）'
    const handle = $('reg-handle') as HTMLInputElement
    handle.value = wallet.handle ? localOf(wallet.handle, wallet.label) : ''
    showView('register')
  })()
}

// ---------------------------------------------------------------------------
// Sign list
// ---------------------------------------------------------------------------
function renderSignList(
  pending: PendingRequest[],
  unlocked: boolean,
  account: StoredAccount | null,
  activeRef: ActiveKeyRef | null,
) {
  const list = $('sign-list')
  list.textContent = ''
  for (const p of pending) list.appendChild(renderSignItem(p, unlocked, account, activeRef))
}

function renderSignItem(
  p: PendingRequest,
  unlocked: boolean,
  account: StoredAccount | null,
  activeRef: ActiveKeyRef | null,
): HTMLLIElement {
  const li = document.createElement('li')

  const top = document.createElement('div')
  top.className = 'method'
  li.appendChild(top)

  const url = document.createElement('div')
  url.className = 'url'
  url.textContent = p.url
  li.appendChild(url)

  const preview = document.createElement('div')
  preview.className = 'preview'
  preview.textContent = p.bodyPreview
  li.appendChild(preview)

  // Unlocked + an account → let the user pick WHICH key/DID signs this request.
  const issuable = account && account.wallets.length > 0 && account.wallets.some((w) => w.keys.length > 0)
  if (unlocked && issuable) {
    const select = document.createElement('select')
    select.className = 'sign-key'
    select.setAttribute('aria-label', '选择签名密钥')
    const opts: { value: string; walletId: string; keyIndex: number; did: string; label: string }[] = []
    for (const w of account!.wallets) {
      for (const key of w.keys) {
        const ki = w.keys.indexOf(key)
        opts.push({
          value: `${w.id}:${ki}`,
          walletId: w.id,
          keyIndex: ki,
          did: key.did,
          label: `${w.label} · key#${key.index} · ${short(key.did, 22)}`,
        })
      }
    }
    for (const o of opts) {
      const op = document.createElement('option')
      op.value = o.value
      op.textContent = o.label
      select.appendChild(op)
    }
    const preselect = activeRef ? `${activeRef.walletId}:${activeRef.keyIndex}` : ''
    if (preselect && opts.some((o) => o.value === preselect)) select.value = preselect
    else if (opts.length) select.value = opts[0].value

    const sync = () => {
      const cur = opts.find((o) => o.value === select.value)
      top.textContent = cur ? `${p.method} · ${cur.did}` : `${p.method} · ${p.did}`
    }
    select.addEventListener('change', sync)
    sync()

    const label = document.createElement('label')
    label.className = 'sign-key-label'
    label.textContent = '用这把密钥签名'
    li.appendChild(label)
    li.appendChild(select)

    const actions = document.createElement('div')
    actions.className = 'actions'

    const approve = document.createElement('button')
    approve.className = 'approve'
    approve.textContent = '批准并签名'
    approve.addEventListener('click', async () => {
      approve.disabled = true
      const cur = opts.find((o) => o.value === select.value)
      await send({ type: 'anp-wallet/approve', id: p.id, sel: cur ? { walletId: cur.walletId, keyIndex: cur.keyIndex } : undefined })
      await render()
    })

    const reject = document.createElement('button')
    reject.className = 'reject'
    reject.textContent = '拒绝'
    reject.addEventListener('click', async () => {
      reject.disabled = true
      await send({ type: 'anp-wallet/reject', id: p.id })
      await render()
    })

    actions.append(approve, reject)
    li.appendChild(actions)
  } else {
    top.textContent = `${p.method} · ${p.did}`
  }

  return li
}

// ---------------------------------------------------------------------------
// small UI helpers
// ---------------------------------------------------------------------------
function confirmBtn(text: string, onConfirm: () => Promise<void>): HTMLButtonElement {
  const b = document.createElement('button')
  b.textContent = text
  let stage = 0
  b.addEventListener('click', async () => {
    stage = (stage + 1) % 2
    b.textContent = stage === 1 ? '确认删除？' : text
    b.style.color = stage === 1 ? 'var(--err)' : ''
    if (stage === 1) {
      setTimeout(() => {
        stage = 0
        b.textContent = text
        b.style.color = ''
      }, 2500)
      return
    }
    await onConfirm()
  })
  return b
}

function btn(text: string, onclick: () => Promise<unknown> | void): HTMLButtonElement {
  const b = document.createElement('button')
  b.textContent = text
  b.addEventListener('click', () => void onclick())
  return b
}

async function withDelayedRender(p: Promise<unknown>) {
  await p
  await render()
}

function wireEvents() {
  // Home: add wallet, lock, export
  $('btn-add-wallet').addEventListener('click', () => showView('addwallet'))
  $('btn-lock').addEventListener('click', async () => {
    await send({ type: 'anp-wallet/lock' })
    await render()
  })
  $('btn-export').addEventListener('click', async () => {
    const resp = await send<{ status?: string; mnemonic?: string; error?: string }>({
      type: 'anp-wallet/export-mnemonic',
    })
    const box = $('export-box')
    if (resp.status === 'ok' && resp.mnemonic) {
      box.textContent = resp.mnemonic
      box.classList.remove('hidden')
    } else {
      box.textContent = resp.error ?? '导出失败'
      box.classList.remove('hidden')
    }
  })

  // Wallet detail: back, rename, register, add-key, delete-wallet
  $('btn-wallet-back').addEventListener('click', () => goHome())
  $('btn-wallet-rename').addEventListener('click', async () => {
    const state = await send<State>({ type: 'anp-wallet/get-state' })
    const walletId = detailWalletId || state.activeRef?.walletId
    const wallet = walletId ? walletById(state.account!, walletId) : null
    if (!walletId || !wallet) return
    const label = (prompt('钱包名称', wallet.label) ?? '').trim()
    if (!label || label === wallet.label) return
    const resp = await send<{ status: string; error?: string }>({ type: 'anp-wallet/rename-wallet', walletId, label })
    if (resp.status !== 'ok') alert(resp.error ?? '重命名失败')
    await render()
  })
  $('btn-wallet-register').addEventListener('click', async () => {
    const state = await send<State>({ type: 'anp-wallet/get-state' })
    const walletId = detailWalletId || state.activeRef?.walletId || state.account?.activeWalletId
    if (walletId) goRegister(walletId)
  })
  $('btn-add-key').addEventListener('click', async () => {
    const state = await send<State>({ type: 'anp-wallet/get-state' })
    const walletId = detailWalletId || state.activeRef?.walletId || state.account?.activeWalletId
    if (!walletId) return
    await send({ type: 'anp-wallet/add-key', walletId })
    await render()
  })
  $('btn-wallet-delete').addEventListener('click', async () => {
    const walletId = detailWalletId
    if (!walletId) return
    if (!confirm('删除这个钱包？它将移除该钱包下的所有密钥与注册数据。')) return
    const resp = await send<{ status: string; error?: string }>({ type: 'anp-wallet/delete-wallet', walletId })
    if (resp.status !== 'ok') {
      alert(resp.error ?? '删除失败')
      return
    }
    detailWalletId = null
    await render()
  })

  // Add-wallet view
  $('btn-addwallet-generate').addEventListener('click', () => {
    ;($('add-mnemonic') as HTMLTextAreaElement).value = generateMnemonicPhrase(256)
  })
  $('btn-addwallet-add').addEventListener('click', async () => {
    const mnemonic = ($('add-mnemonic') as HTMLTextAreaElement).value.trim()
    const handle = ($('add-handle') as HTMLInputElement).value.trim()
    const err = $('addwallet-err')
    err.textContent = ''
    const resp = await send<{ status: string; error?: string }>({
      type: 'anp-wallet/add-wallet',
      mnemonic,
      handle: handle || undefined,
    })
    if (resp.status !== 'ok') {
      err.textContent = String(resp.error ?? '添加失败')
      return
    }
    await render()
    goHome()
  })
  $('btn-addwallet-back').addEventListener('click', () => {
    void render()
  })

  // Register view
  $('btn-register').addEventListener('click', async () => {
    const err = $('reg-status')
    err.textContent = ''
    const walletId = regWalletId
    if (!walletId) {
      err.textContent = '请选择一个钱包'
      return
    }
    const handle = ($('reg-handle') as HTMLInputElement).value.trim()
    if (!handle) {
      err.textContent = '请先填写 handle 名字'
      return
    }
    const resp = await send<{ status: string; error?: string; did?: string }>({
      type: 'anp-wallet/register',
      walletId,
      handle,
    })
    if (resp.status !== 'ok') {
      err.textContent = String(resp.error ?? '注册失败')
      return
    }
    err.textContent = '✓ 注册成功'
    regWalletId = null
    await render()
  })
  $('btn-register-back').addEventListener('click', () => {
    regWalletId = null
    void render()
  })

  // Create
  $('btn-generate').addEventListener('click', () => {
    ;($('mnemonic') as HTMLTextAreaElement).value = generateMnemonicPhrase(256)
  })
  $('btn-create').addEventListener('click', async () => {
    const mnemonic = ($('mnemonic') as HTMLTextAreaElement).value.trim()
    const password = ($('wallet-password') as HTMLInputElement).value
    const err = $('create-err')
    err.textContent = ''
    const resp = await send<{ status: string; error?: string }>({
      type: 'anp-wallet/create-account',
      mnemonic,
      password,
    })
    if (resp.status !== 'ok') {
      err.textContent = String(resp.error ?? '创建失败')
      return
    }
    await render()
  })

  // Unlock
  $('btn-unlock').addEventListener('click', async () => {
    const password = ($('unlock-password') as HTMLInputElement).value
    const err = $('unlock-err')
    err.textContent = ''
    const resp = await send<{ status: string; error?: string }>({ type: 'anp-wallet/unlock', password })
    if (resp.status !== 'ok') {
      err.textContent = String(resp.error ?? '解锁失败')
      return
    }
    await render()
  })
}

wireEvents()
void render()
