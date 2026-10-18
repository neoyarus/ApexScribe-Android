package com.windscribe.mobile.ui.nav

import androidx.compose.animation.AnimatedContentScope
import androidx.compose.animation.AnimatedContentTransitionScope
import androidx.compose.animation.EnterTransition
import androidx.compose.animation.ExitTransition
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.navigation.NavBackStackEntry
import androidx.navigation.NavGraphBuilder
import com.windscribe.vpn.BuildConfig
import androidx.navigation.compose.composable as navigationComposable

private typealias EnterTransform = AnimatedContentTransitionScope<NavBackStackEntry>.() -> EnterTransition
private typealias ExitTransform = AnimatedContentTransitionScope<NavBackStackEntry>.() -> ExitTransition

/** Standard horizontal slide transitions shared by most navigation screens. */
private val slideEnter: EnterTransform = { slideInHorizontally(initialOffsetX = { -it }) }
private val slideExit: ExitTransform = { slideOutHorizontally(targetOffsetX = { it }) }
private val slidePopEnter: EnterTransform = { slideInHorizontally(initialOffsetX = { it }) }
private val slidePopExit: ExitTransform = { slideOutHorizontally(targetOffsetX = { -it }) }

/** Apply the provider route policy before screen content can create a ViewModel. */
internal fun NavGraphBuilder.guardedComposable(
    route: String,
    enterTransition: EnterTransform? = null,
    exitTransition: ExitTransform? = null,
    popEnterTransition: EnterTransform? = null,
    popExitTransition: ExitTransform? = null,
    content: @Composable AnimatedContentScope.(NavBackStackEntry) -> Unit,
) = navigationComposable(
    route = route,
    enterTransition = enterTransition,
    exitTransition = exitTransition,
    popEnterTransition = popEnterTransition,
    popExitTransition = popExitTransition,
) { entry ->
    if (ApexNavigationPolicy.isAllowed(route, BuildConfig.APEXGUARD_ENABLED)) {
        content(entry)
    } else {
        val navController = LocalNavController.current
        LaunchedEffect(entry) {
            if (navController.currentBackStackEntry != entry) return@LaunchedEffect
            val previousRoute = navController.previousBackStackEntry?.destination?.route
            if (previousRoute != null && ApexNavigationPolicy.isAllowed(previousRoute, true)) {
                navController.popBackStack()
            } else {
                navController.navigate(Screen.Home.route) {
                    popUpTo(navController.graph.id)
                    launchSingleTop = true
                }
            }
        }
    }
}

/**
 * Like [guardedComposable] but applies the standard horizontal slide transitions, so the
 * four enter/exit lambdas don't have to be repeated at every call site. Any of the
 * four can be overridden for screens that need a different animation.
 */
fun NavGraphBuilder.slidingComposable(
    route: String,
    enterTransition: EnterTransform = slideEnter,
    exitTransition: ExitTransform = slideExit,
    popEnterTransition: EnterTransform = slidePopEnter,
    popExitTransition: ExitTransform = slidePopExit,
    content: @Composable AnimatedContentScope.(NavBackStackEntry) -> Unit,
) = guardedComposable(
    route = route,
    enterTransition = enterTransition,
    exitTransition = exitTransition,
    popEnterTransition = popEnterTransition,
    popExitTransition = popExitTransition,
    content = content,
)
