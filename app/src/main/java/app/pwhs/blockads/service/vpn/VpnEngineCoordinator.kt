package app.pwhs.blockads.service.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.os.ParcelFileDescriptor
import app.pwhs.blockads.data.dao.FirewallRuleDao
import app.pwhs.blockads.data.datastore.AppPreferences
import app.pwhs.blockads.data.entities.DnsProtocol
import app.pwhs.blockads.data.repository.FilterListRepository
import app.pwhs.blockads.service.FirewallManager
import app.pwhs.blockads.service.GoTunnelAdapter
import app.pwhs.blockads.service.TrustedNetworkManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import timber.log.Timber

data class StartupConfig(
    val upstreamDns: String,
    val fallbackDns: String,
    val dnsResponseType: String,
    val dnsProtocol: DnsProtocol,
    val dohUrl: String,
    val whitelistedApps: Set<String>,
    val safeSearchEnabled: Boolean,
    val youtubeRestrictedMode: Boolean,
    val firewallEnabled: Boolean,
    val dnsProviderId: String?,
    val firewallManager: FirewallManager?,
    val odohRelayUrl: String = ""
)

class VpnEngineCoordinator(
    private val context: Context,
    private val appPrefs: AppPreferences,
    private val filterRepo: FilterListRepository,
    private val firewallRuleDao: FirewallRuleDao
) {

    suspend fun prepareStartupConfig(): StartupConfig {
        filterRepo.loadWhitelist()
        filterRepo.loadCustomRules()
        filterRepo.seedDefaultsIfNeeded()
        filterRepo.fetchAndSyncRemoteFilterLists()
        val filterResult = filterRepo.loadAllEnabledFilters()
        Timber.d("Filters loaded: ${filterResult.getOrDefault(0)} domains")

        return coroutineScope {
            val d1 = async { appPrefs.upstreamDns.first() }
            val d2 = async { appPrefs.fallbackDns.first() }
            val d3 = async { appPrefs.dnsResponseType.first() }
            val d4 = async { appPrefs.dnsProtocol.first() }
            val d5 = async { appPrefs.dohUrl.first() }
            val d6 = async { appPrefs.getWhitelistedAppsSnapshot() }
            val d7 = async { appPrefs.safeSearchEnabled.first() }
            val d8 = async { appPrefs.youtubeRestrictedMode.first() }
            val d9 = async { appPrefs.firewallEnabled.first() }
            val d10 = async { appPrefs.dnsProviderId.first() }
            val d11 = async { appPrefs.odohRelayUrl.first() }

            val firewallEnabled = d9.await()
            val fwManager = if (firewallEnabled) {
                FirewallManager(context, firewallRuleDao).also {
                    it.loadRules()
                    Timber.d("Firewall enabled, rules loaded")
                }
            } else {
                null
            }

            StartupConfig(
                upstreamDns = d1.await(),
                fallbackDns = d2.await(),
                dnsResponseType = d3.await(),
                dnsProtocol = d4.await(),
                dohUrl = d5.await(),
                whitelistedApps = d6.await(),
                safeSearchEnabled = d7.await(),
                youtubeRestrictedMode = d8.await(),
                firewallEnabled = firewallEnabled,
                dnsProviderId = d10.await(),
                firewallManager = fwManager,
                odohRelayUrl = d11.await()
            )
        }
    }

    suspend fun configureEngine(goTunnelAdapter: GoTunnelAdapter, config: StartupConfig) {
        var finalUpstreamDns = config.upstreamDns
        var finalFallbackDns = config.fallbackDns
        var finalDnsProtocol = config.dnsProtocol.name

        val onTrustedWithSystemDns = isTrustedNetworkWithSystemDns()
        if (config.dnsProviderId == "system" || onTrustedWithSystemDns) {
            val systemDnsList = getSystemDnsServers(context)
            val (primary, fallback) = resolveSystemDnsPair(systemDnsList, config.fallbackDns)
            finalUpstreamDns = primary
            finalFallbackDns = fallback
            Timber.d("System DNS resolved to primary: $finalUpstreamDns, fallback: $finalFallbackDns (onTrusted=$onTrustedWithSystemDns)")
            finalDnsProtocol = "PLAIN"
        }

        goTunnelAdapter.configureDns(
            protocol = finalDnsProtocol,
            primary = finalUpstreamDns,
            fallback = finalFallbackDns,
            dohUrl = config.dohUrl,
            odohRelayUrl = config.odohRelayUrl
        )
        goTunnelAdapter.setBlockResponseType(config.dnsResponseType)
        goTunnelAdapter.configureSafeSearch(config.safeSearchEnabled, config.youtubeRestrictedMode)

        val splitDnsZones = appPrefs.splitDnsZones.first()
        goTunnelAdapter.setSplitDNSZones(splitDnsZones)
    }

    suspend fun isTrustedNetworkWithSystemDns(): Boolean {
        if (!appPrefs.getUseSystemDnsOnTrustedEnabledSnapshot()) return false
        val ssid = TrustedNetworkManager.currentSsid(context) ?: return false
        val trusted = appPrefs.getTrustedSsidsSnapshot()
        return ssid in trusted
    }

    suspend fun reloadDns(goTunnelAdapter: GoTunnelAdapter) {
        val providerId = appPrefs.dnsProviderId.first()
        val onTrustedWithSystemDns = isTrustedNetworkWithSystemDns()
        val configuredFallback = appPrefs.fallbackDns.first()
        val dohUrl = appPrefs.dohUrl.first()
        val odohRelayUrl = appPrefs.odohRelayUrl.first()

        if (providerId == "system" || onTrustedWithSystemDns) {
            val systemDnsList = getSystemDnsServers(context)
            val (primary, fallback) = resolveSystemDnsPair(systemDnsList, configuredFallback)
            Timber.d("Reloading DNS -> System DNS (primary: $primary, fallback: $fallback, onTrusted=$onTrustedWithSystemDns)")
            goTunnelAdapter.configureDns(
                protocol = "PLAIN",
                primary = primary,
                fallback = fallback,
                dohUrl = dohUrl,
                odohRelayUrl = odohRelayUrl
            )
        } else {
            val upstreamDns = appPrefs.upstreamDns.first()
            val dnsProtocol = appPrefs.dnsProtocol.first().name
            Timber.d("Reloading DNS -> Configured DNS ($dnsProtocol, primary: $upstreamDns, fallback: $configuredFallback)")
            goTunnelAdapter.configureDns(
                protocol = dnsProtocol,
                primary = upstreamDns,
                fallback = configuredFallback,
                dohUrl = dohUrl,
                odohRelayUrl = odohRelayUrl
            )
        }
    }

    suspend fun startTunnel(
        goTunnelAdapter: GoTunnelAdapter,
        vpnInterface: ParcelFileDescriptor,
        resolvedWgConfigJson: String,
        httpsFilteringEnabled: Boolean,
        certDir: String,
        socketProtector: (Int) -> Boolean
    ) {
        val routingMode = appPrefs.getRoutingModeSnapshot()
        val wgConfigJson = if (routingMode == AppPreferences.ROUTING_MODE_WIREGUARD) {
            resolvedWgConfigJson.ifEmpty { appPrefs.getWgConfigJsonSnapshot() ?: "" }
        } else {
            ""
        }

        val selectedBrowsers = appPrefs.getSelectedBrowsersSnapshot()
        val filterHttp3 = if (httpsFilteringEnabled) true else appPrefs.getFilterHttp3Snapshot()
        val blockDohBypass = appPrefs.getBlockDohBypassSnapshot()

        goTunnelAdapter.start(
            vpnInterface = vpnInterface,
            wgConfigJson = wgConfigJson,
            httpsFilteringEnabled = httpsFilteringEnabled,
            selectedBrowsers = selectedBrowsers,
            certDir = certDir,
            filterHttp3 = filterHttp3,
            blockDohBypass = blockDohBypass,
            socketProtector = socketProtector
        )
    }

    suspend fun handleLinkPropertiesChanged(
        goTunnelAdapter: GoTunnelAdapter,
        linkProperties: LinkProperties?
    ) {
        val providerId = appPrefs.dnsProviderId.first()
        val onTrustedWithSystemDns = isTrustedNetworkWithSystemDns()
        if (providerId == "system" || onTrustedWithSystemDns) {
            val newDns = linkProperties?.dnsServers?.mapNotNull { it.hostAddress }
                ?.filter { it.isNotEmpty() } ?: emptyList()
            val configuredFallback = appPrefs.fallbackDns.first()
            val (primary, fallback) = resolveSystemDnsPair(newDns, configuredFallback)
            Timber.d("Network LinkProperties changed, hot-reloading System DNS primary: $primary, fallback: $fallback")
            val dohUrl = appPrefs.dohUrl.first()
            val odohRelayUrl = appPrefs.odohRelayUrl.first()
            goTunnelAdapter.configureDns(
                protocol = "PLAIN",
                primary = primary,
                fallback = fallback,
                dohUrl = dohUrl,
                odohRelayUrl = odohRelayUrl
            )
        }
    }

    fun startFilterUpdateWatcher(scope: CoroutineScope, goTunnelAdapter: GoTunnelAdapter) {
        scope.launch {
            filterRepo.domainCountFlow.drop(1).collectLatest { count ->
                Timber.d("Filter count changed to $count. Dynamically updating Native Go Tries.")
                goTunnelAdapter.updateTries()
            }
        }
    }

    private fun resolveSystemDnsPair(dnsList: List<String>, configuredFallback: String): Pair<String, String> {
        if (dnsList.isEmpty()) {
            return Pair("8.8.8.8", configuredFallback.ifEmpty { "1.1.1.1" })
        }
        val ipv4List = dnsList.filter { !it.contains(":") }
        val ipv6List = dnsList.filter { it.contains(":") }

        // Prefer IPv4 as primary for stability when ISP doesn't prefer or support IPv6
        val primary = ipv4List.firstOrNull() ?: dnsList.first()
        val fallback = if (primary in ipv4List) {
            ipv4List.getOrNull(1) ?: ipv6List.firstOrNull() ?: configuredFallback.ifEmpty { "1.1.1.1" }
        } else {
            ipv4List.firstOrNull() ?: dnsList.getOrNull(1) ?: configuredFallback.ifEmpty { "1.1.1.1" }
        }
        return Pair(primary, fallback)
    }

    private fun getSystemDnsServers(context: Context): List<String> {
        val connectivityManager =
            context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        val activeNetwork = connectivityManager?.activeNetwork ?: return emptyList()
        val linkProperties = connectivityManager.getLinkProperties(activeNetwork) ?: return emptyList()
        return linkProperties.dnsServers.mapNotNull { it.hostAddress }.filter { it.isNotEmpty() }
    }
}
