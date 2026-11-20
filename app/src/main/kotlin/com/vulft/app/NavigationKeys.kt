package com.vulft.app

import androidx.navigation3.runtime.NavKey
import kotlinx.serialization.Serializable

@Serializable data object CveListRoute : NavKey
@Serializable data class CveDetailRoute(val cveId: String) : NavKey
@Serializable data object SettingsRoute : NavKey
@Serializable data object AppPickerRoute : NavKey
@Serializable data object SmtpRoute : NavKey
@Serializable data object AlertRulesRoute : NavKey
@Serializable data object CatalogRoute : NavKey
@Serializable data object PermissionsRoute : NavKey
@Serializable data object CveSearchRoute : NavKey
