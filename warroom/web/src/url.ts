// 相对路径 URL 拼接：若以 http 开头直接开，否则拼主攻资产 host
export function resolveUrl(url: string, focusHost: string | null): string | null {
  if (!url) return null
  if (/^https?:\/\//i.test(url)) return url
  if (!focusHost) return null
  const host = focusHost.replace(/^https?:\/\//i, '')
  return `https://${host}${url.startsWith('/') ? url : '/' + url}`
}

export function openUrl(url: string, focusHost: string | null) {
  const resolved = resolveUrl(url, focusHost)
  if (resolved) window.open(resolved, '_blank', 'noopener')
  return !!resolved
}
