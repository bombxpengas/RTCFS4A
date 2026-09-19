package com.example.filecorruptor

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BrokenImage
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.example.filecorruptor.engine.EngineViewModel
import com.example.filecorruptor.ui.CorruptorScreen
import com.example.filecorruptor.ui.LiveMemoryScreen
import com.example.filecorruptor.ui.SettingsScreen
import com.example.filecorruptor.ui.theme.FileCorruptorTheme

private sealed class Destination(val route: String, val label: String) {
    data object Corruptor : Destination("corruptor", "Corruptor")
    data object LiveMemory : Destination("live", "Live RAM")
    data object Settings : Destination("settings", "Settings")
}

private val destinations = listOf(Destination.Corruptor, Destination.LiveMemory, Destination.Settings)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            FileCorruptorTheme {
                AppRoot()
            }
        }
    }
}

@Composable
private fun AppRoot() {
    val navController = rememberNavController()

    // Resolved here (composed directly under the Activity, not inside a
    // NavHost destination) so it's Activity-scoped and shared by both tabs.
    // If each screen instead called viewModel() with no argument itself,
    // Navigation-Compose would scope each call to that destination's own
    // NavBackStackEntry, handing Corruptor and Settings two *separate*
    // instances — silently breaking the "selection and parameter values
    // persist across tabs" behavior this app depends on.
    val engineViewModel: EngineViewModel = viewModel()

    Scaffold(
        bottomBar = {
            NavigationBar {
                val navBackStackEntry by navController.currentBackStackEntryAsState()
                val currentDestination = navBackStackEntry?.destination

                destinations.forEach { dest ->
                    val selected = currentDestination?.hierarchy?.any { it.route == dest.route } == true
                    NavigationBarItem(
                        selected = selected,
                        onClick = {
                            navController.navigate(dest.route) {
                                popUpTo(navController.graph.findStartDestination().id) {
                                    saveState = true
                                }
                                launchSingleTop = true
                                restoreState = true
                            }
                        },
                        icon = {
                            Icon(
                                when (dest) {
                                    is Destination.Corruptor -> Icons.Filled.BrokenImage
                                    is Destination.LiveMemory -> Icons.Filled.Memory
                                    is Destination.Settings -> Icons.Filled.Settings
                                },
                                contentDescription = dest.label
                            )
                        },
                        label = { Text(dest.label) }
                    )
                }
            }
        }
    ) { innerPadding ->
        NavHost(
            navController = navController,
            startDestination = Destination.Corruptor.route,
            modifier = Modifier.padding(innerPadding)
        ) {
            composable(Destination.Corruptor.route) { CorruptorScreen(engineViewModel) }
            composable(Destination.LiveMemory.route) { LiveMemoryScreen(engineViewModel) }
            composable(Destination.Settings.route) { SettingsScreen(engineViewModel) }
        }
    }
}
