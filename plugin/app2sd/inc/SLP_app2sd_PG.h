/*
 * app2sd
 *
 * Copyright (c) 2012 - 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Garima Shrivastava<garima.s@samsung.com>
 *	Jyotsna Dhumale <jyotsna.a@samsung.com>
 *	Venkatesha Sarpangala <sarpangala.v@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/**
 *
 * @ingroup SLP_PG
 * @defgroup app2sd_PG App2sd
 * @{

<h1 class="pg">Introduction</h1>
App2sd is a feature that enables package installers to install applications on sdcard.
It also provides API to move installed applications from sd card to internal memory and vice versa.
App2sd provides an API for validating the integrity of the package before launching by the launchpad.

<h1 class="pg">App2sd process view</h1>
\image html app2sd_diag.png "Picture 1. Process View Diagram"
\image rtf app2sd_diag.png "Picture 1. Process View Diagram"

<h1 class="pg">Installation to SD Card</h1>
Package installer should call the App2sd pre-install setup API before installation.
This API creates directory structure in SD card.
Refer to Picture 2. for flow diagram.

<h1 class="pg">App2sd Installation Setup  Flow</h1>
\image html app2sd_install_diag.png "Picture 2. Installation Flow  Diagram"
\image rtf app2sd_install_diag.png "Picture 2. Installation Flow  Diagram"

<h1 class="pg">Uninstallation to SD Card</h1>
Package installer should call the App2sd pre-uninstall setup API before uninstallation.
Once the uninstallation is done by the package installer
then App2sd post-uninstall setup API should be called.
This API will clean up the directory structure and remove password from sqlite db.
Refer to Picture 3. for flow diagram.
<h1 class="pg">App2sd Uninstallation Setup  Flow</h1>
\image html app2sd_uninstall_diag.png "Picture 3. Uninstallation Flow Diagram"
\image rtf app2sd_uninstall_diag.png "Picture 3. Uninstallation Flow Diagram"

<h1 class="pg">API list and description</h1>
<ul>
	<li>app2sd_pre_app_install() : Pre app installation setup.</li>
	<li>app2sd_post_app_install() : Post app installation setup.</li>
	<li>app2sd_pre_app_upgrade() : Pre app upgrade setup.</li>
	<li>app2sd_post_app_upgrade() : Post app upgarde setup.</li>
	<li>app2sd_pre_app_uninstall() : Pre app uninstall setup.</li>
	<li>app2sd_post_app_uninstall() : Post app uninstall setup.</li>
	<li>app2sd_move_installed_app() : Move installed application to/from sdcard</li>
	<li>app2sd_get_app_install_location() : Get application installation location[external\internal memory].</li>
	<li>app2sd_on_demand_setup_init() : Enables the application installed in sdcard.</li>
	<li>app2sd_on_demand_setup_exit() : Disables the application installed in sdcard.</li>
	<li></li>
</ul>

 * @}
 */
