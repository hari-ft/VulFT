package com.vulft.app

import androidx.compose.runtime.Composable
import androidx.navigation3.runtime.entryProvider
import androidx.navigation3.runtime.rememberNavBackStack
import androidx.navigation3.ui.NavDisplay
import com.vulft.app.ui.apps.AppPickerScreen
import com.vulft.app.ui.catalog.CatalogScreen
import com.vulft.app.ui.detail.CveDetailScreen
import com.vulft.app.ui.list.CveListScreen
import com.vulft.app.ui.search.CveSearchScreen
import com.vulft.app.ui.settings.AlertRulesScreen
import com.vulft.app.ui.settings.SettingsScreen
import com.vulft.app.ui.settings.SmtpScreen

@Composable
fun MainNavigation(openCve: String? = null, onCveOpened: () -> Unit = {}) {
  val backStack = rememberNavBackStack(CveListRoute)
  val back: () -> Unit = { backStack.removeLastOrNull() }
  // A tapped notification opens that CVE on top of the list.
  androidx.compose.runtime.LaunchedEffect(openCve) {
    if (openCve != null) { backStack.add(CveDetailRoute(openCve)); onCveOpened() }
  }

  NavDisplay(
    backStack = backStack,
    onBack = back,
    entryProvider = entryProvider {
      entry<CveListRoute> {
        CveListScreen(
          onOpenCve = { backStack.add(CveDetailRoute(it)) },
          onOpenSettings = { backStack.add(SettingsRoute) },
          onOpenApps = { backStack.add(AppPickerRoute) },
          onOpenSearch = { backStack.add(CveSearchRoute) },
          onOpenCatalog = { backStack.add(CatalogRoute) },
        )
      }
      entry<CveSearchRoute> { CveSearchScreen(onBack = back, onOpenCve = { backStack.add(CveDetailRoute(it)) }) }
      entry<CveDetailRoute> { key -> CveDetailScreen(cveId = key.cveId, onBack = back) }
      entry<SettingsRoute> {
        SettingsScreen(
          onBack = back,
          onOpenApps = { backStack.add(AppPickerRoute) },
          onOpenCatalog = { backStack.add(CatalogRoute) },
          onOpenSmtp = { backStack.add(SmtpRoute) },
          onOpenAlerts = { backStack.add(AlertRulesRoute) },
          onOpenPermissions = { backStack.add(PermissionsRoute) },
        )
      }
      entry<PermissionsRoute> { com.vulft.app.ui.settings.PermissionsScreen(onBack = back) }
      entry<AppPickerRoute> { AppPickerScreen(onBack = back, onOpenCatalog = { backStack.add(CatalogRoute) }) }
      entry<CatalogRoute> { CatalogScreen(onBack = back) }
      entry<SmtpRoute> { SmtpScreen(onBack = back) }
      entry<AlertRulesRoute> { AlertRulesScreen(onBack = back) }
    },
  )
}
