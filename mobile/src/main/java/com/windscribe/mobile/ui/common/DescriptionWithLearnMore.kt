package com.windscribe.mobile.ui.common

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.LinkAnnotation
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextLinkStyles
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.withLink
import com.windscribe.mobile.ui.theme.AppColors
import com.windscribe.mobile.ui.theme.font14
import com.windscribe.mobile.ui.theme.preferencesSubtitleColor
import com.windscribe.vpn.BuildConfig
import java.net.URI

@Composable
fun DescriptionWithLearnMore(
    description: String,
    path: String,
) {
    val context = LocalContext.current
    val vendorLink =
        runCatching {
            val host = URI(path).host.orEmpty().lowercase()
            host == "windscribe.com" || host.endsWith(".windscribe.com")
        }.getOrDefault(false)
    val annotatedString =
        buildAnnotatedString {
            append("$description ")
            if (!BuildConfig.APEXGUARD_ENABLED || !vendorLink) {
                withLink(
                    LinkAnnotation.Clickable(
                        tag = "LEARN_MORE",
                        styles =
                            TextLinkStyles(
                                style =
                                    SpanStyle(
                                        color = AppColors.mediumBlue,
                                        fontWeight = FontWeight.Medium,
                                    ),
                            ),
                        linkInteractionListener = { context.openUrl(path) },
                    ),
                ) {
                    append("Learn more")
                }
            }
        }

    Text(
        text = annotatedString,
        style =
            font14.copy(
                color = MaterialTheme.colorScheme.preferencesSubtitleColor,
                textAlign = TextAlign.Start,
                fontWeight = FontWeight.Normal,
            ),
    )
}
