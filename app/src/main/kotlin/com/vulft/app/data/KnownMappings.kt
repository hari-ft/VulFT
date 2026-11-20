package com.vulft.app.data

/**
 * Built-in Android package -> NVD CPE vendor:product suggestions.
 * These are starting points; the user can verify/change any mapping in Settings > Apps.
 */
object KnownMappings {
  /** Microsoft's Android apps → their product names in the Security Update Guide (MSRC). Linked automatically. */
  val msrc: Map<String, String> = mapOf(
    "com.microsoft.emmx" to "Microsoft Edge for Android",
    "com.microsoft.teams" to "Microsoft Teams for Android",
    "com.microsoft.office.outlook" to "Microsoft Outlook for Android",
    "com.microsoft.office.officehubrow" to "Microsoft Office for Android",
    "com.azure.authenticator" to "Microsoft Authenticator for Android",
    "com.microsoft.office.word" to "Microsoft Word for Android",
    "com.microsoft.office.excel" to "Microsoft Excel for Android",
    "com.microsoft.office.powerpoint" to "Microsoft PowerPoint for Android",
    "com.microsoft.office.onenote" to "Microsoft OneNote for Android",
    "com.microsoft.skydrive" to "OneDrive for Android",
    "com.microsoft.bing" to "Microsoft Bing Search for Android",
    "com.microsoft.scmx" to "Microsoft Defender for Endpoint for Android",
    "com.microsoft.msapps" to "Microsoft Power Apps for Android",
    "com.microsoft.powerbim" to "Microsoft PowerBI for Android",
    "com.microsoft.loop" to "Microsoft Loop for Android",
  )

  val map: Map<String, Pair<String, String>> = mapOf(
    "com.android.chrome" to ("google" to "chrome"),
    "com.google.android.webview" to ("google" to "chrome"),
    "com.chrome.beta" to ("google" to "chrome"),
    "com.google.android.gm" to ("google" to "gmail"),
    "com.google.android.apps.docs" to ("google" to "drive"),
    "com.mxtech.videoplayer.ad" to ("mxplayer" to "mx_player"),
    "com.whatsapp" to ("whatsapp" to "whatsapp"),
    "com.whatsapp.w4b" to ("whatsapp" to "whatsapp_business"),
    "org.telegram.messenger" to ("telegram" to "telegram"),
    "org.thoughtcrime.securesms" to ("signal" to "signal"),
    "com.viber.voip" to ("rakuten" to "viber"),
    "com.tencent.mm" to ("tencent" to "wechat"),
    "com.discord" to ("discord" to "discord"),
    "com.facebook.katana" to ("facebook" to "facebook"),
    "com.facebook.orca" to ("facebook" to "messenger"),
    "com.instagram.android" to ("facebook" to "instagram"),
    "com.zhiliaoapp.musically" to ("tiktok" to "tiktok"),
    "com.twitter.android" to ("twitter" to "twitter"),
    "com.linkedin.android" to ("linkedin" to "linkedin"),
    "us.zoom.videomeetings" to ("zoom" to "meetings"),
    "com.microsoft.teams" to ("microsoft" to "teams"),
    "com.skype.raider" to ("microsoft" to "skype"),
    "com.microsoft.office.outlook" to ("microsoft" to "outlook"),
    "com.microsoft.emmx" to ("microsoft" to "edge_chromium"),
    "org.mozilla.firefox" to ("mozilla" to "firefox"),
    "org.mozilla.focus" to ("mozilla" to "focus"),
    "com.opera.browser" to ("opera" to "opera_browser"),
    "com.brave.browser" to ("brave" to "brave"),
    "com.duckduckgo.mobile.android" to ("duckduckgo" to "duckduckgo"),
    "com.sec.android.app.sbrowser" to ("samsung" to "internet"),
    "com.UCMobile.intl" to ("ucweb" to "uc_browser"),
    "org.videolan.vlc" to ("videolan" to "vlc_media_player"),
    "com.spotify.music" to ("spotify" to "spotify"),
    "com.adobe.reader" to ("adobe" to "acrobat_reader"),
    "cn.wps.moffice_eng" to ("kingsoft" to "wps_office"),
    "com.dropbox.android" to ("dropbox" to "dropbox"),
    "com.paypal.android.p2pmobile" to ("paypal" to "paypal"),
    "com.anydesk.anydeskandroid" to ("anydesk" to "anydesk"),
    "com.teamviewer.teamviewer.market.mobile" to ("teamviewer" to "teamviewer"),
    "com.nordvpn.android" to ("nordvpn" to "nordvpn"),
    "net.openvpn.openvpn" to ("openvpn" to "connect"),
    "com.wireguard.android" to ("wireguard" to "wireguard"),
    "com.x8bit.bitwarden" to ("bitwarden" to "bitwarden"),
  )
}
