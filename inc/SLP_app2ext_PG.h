/*
 * app2ext
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Jyotsna Dhumale <jyotsna.a@samsung.com>
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
 * @defgroup app2ext_PG App2Ext
 * @{

<h1 class="pg">Introduction</h1>
App2Ext is a feature that enables package installers to install applications on external storage like SD card, Micro USB flash drive or Cloud.
It also provides option to move installed applications from external memory to internal memory and vice versa.

<h1 class="pg">App2Ext process view</h1>
\image html app2ext_diag.png "Picture 1. App2Ext Process View Diagram"
\image rtf app2ext_diag.png "Picture 1. App2Ext Process View Diagram"

<h1 class="pg">Installation to SD Card</h1>
Package installer should call the App2Ext's Init API to initialize SD plug-in. Once the plug-in initialization is done App2Ext returns a storage handle to the Package installer. Package installer should then call the pre-install setup API with respect to the storage handle which will be mapped to app2sd's pre-install API. The App2Ext Pre-install API performs the setup required for the installation based on the external storage type.
After pre-install setup is done Package installer can proceed with the installation of the application. When package installation is completed by the package installer, post-install setup API should be called. This API removes the setup created for installation during pre-install API.

Refer to Picture 2. for flow diagram.

<h1 class="pg">Installation Setup Flow for App2SD plug-in</h1>
\image html app2ext_install_diag.png "Picture 2. Installation on SD card Flow Diagram"
\image rtf app2ext_install_diag.png "Picture 2. Installation on SD card Flow Diagram"

<h1 class="pg">Un-installation from SD Card</h1>
Package installer should call the App2Ext's Init API to initialize SD plug-in. Once the plug-in initialization is done App2Ext returns a storage handle to the Package installer. Package installer should then call the pre-uninstall setup API with respect to the storage handle which will be mapped to app2sd's pre-uninstall API. Pre-uninstall API performs the setup required for the package un-installation based on the external storage type.
After pre-uninstall setup is done Package installer can proceed with un-installation of the package. When package un-installation is completed by the package installer, post-uninstall setup API should be called. This API removes the setup created for un-installation during pre-uninstall API.

Refer to Picture 3. for flow diagram.

<h1 class="pg">Un-installation Setup Flow for App2SD plug-in</h1>
\image html app2ext_uninstall_diag.png "Picture 3. Un-installation from SD card Flow Diagram"
\image rtf app2ext_uninstall_diag.png "Picture 3. Un-installation from SD card Flow Diagram"


<h1 class="pg">API list and description</h1>
<ul>
	<li>app2ext_init() : Initialize plug-in based on storage type </li>
	<li>app2ext_deinit() : De-initialize plug-in</li>
	<li>app2ext_get_app_location() : Returns application current location</li>
</ul>

 * @}
 */
