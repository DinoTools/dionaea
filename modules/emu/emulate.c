/********************************************************************************
 *                               Dionaea
 *                           - catches bugs -
 *
 *
 *
 * Copyright (C) 2009  Paul Baecher & Markus Koetter
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 * 
 * 
 *             contact nepenthesdev@gmail.com  
 *
 *******************************************************************************/

/********************************************************************************
 *                               Dionaea
 *                           - catches bugs -
 *
 *
 *
 * Copyright (C) 2009  Paul Baecher & Markus Koetter
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 * 
 * 
 *             contact nepenthesdev@gmail.com  
 *
 *******************************************************************************/

#include <stdint.h>

#include <emu/emu.h>
#include <emu/emu_memory.h>
#include <emu/emu_cpu.h>
#include <emu/emu_log.h>
#include <emu/emu_cpu_data.h>
#include <emu/emu_cpu_stack.h>
#include <emu/environment/emu_profile.h>
#include <emu/environment/emu_env.h>
#include <emu/environment/win32/emu_env_w32.h>
#include <emu/environment/win32/emu_env_w32_dll.h>
#include <emu/environment/win32/emu_env_w32_dll_export.h>
#include <emu/environment/win32/env_w32_dll_export_kernel32_hooks.h>
#include <emu/environment/linux/emu_env_linux.h>
#include <emu/emu_getpc.h>
#include <emu/emu_string.h>
#include <emu/emu_shellcode.h>


int run(struct emu *e, struct emu_env *env)
{


	int j=0;
	int ret; //= emu_cpu_run(emu_cpu_get(e));



	for ( j=0;j< 1000000;j++ )
	{
		struct emu_env_hook *hook = NULL;
		hook = emu_env_w32_eip_check(env);

		if ( hook != NULL )
		{
			if ( hook->hook.win->fnhook == NULL )
			{
				printf("unhooked call to %s\n", hook->hook.win->fnname);
				break;
			}
		}
		else
		{
			ret = emu_cpu_parse(emu_cpu_get(e));
			struct emu_env_hook *hook =NULL;
			if ( ret != -1 )
			{
				hook = emu_env_linux_syscall_check(env);
				if ( hook == NULL )
				{
					ret = emu_cpu_step(emu_cpu_get(e));
				}
				else
				{
					if ( hook->hook.lin->fnhook != NULL )
						hook->hook.lin->fnhook(env, hook);
					else
						break;
				}
			}

			if ( ret == -1 )
			{
				printf("cpu error %s\n", emu_strerror(e));
				break;
			}
		}
	}

	return 0;
}
