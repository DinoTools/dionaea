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

#include <glib.h>
#include <ev.h>

#include "module.h"
#include "incident.h"
#include "threads.h"
#include "dionaea.h"
#include "connection.h"


#define	CODE_OFFSET 0x417000

char *indents(int i)
{
	static char indents[255];
	memset(indents, ' ', 255);
	indents[i*4] = '\0';
	return indents;
}

void json_profile_argument_debug(struct emu_profile_argument *argument, int indent, bool has_name, GString *str)
{
	switch(argument->render)
	{
	case render_struct:
		if( has_name )
			g_string_append_printf(str, "%*s\"%s\" : {\n", indent*4, " ", argument->argname);
//			printf("%*s\"%s\" : {\n", indent*4, " ", argument->argname);
		else
			g_string_append_printf(str, "%*s{\n", indent*4, " ");
//			printf("%*s{\n", indent*4, " ");


		struct emu_profile_argument *argumentit;
		for (argumentit = emu_profile_arguments_first(argument->value.tstruct.arguments); 
			  !emu_profile_arguments_istail(argumentit); 
			  argumentit = emu_profile_arguments_next(argumentit))
		{
			if(argumentit != emu_profile_arguments_first(argument->value.tstruct.arguments))
				g_string_append_printf(str, ",\n");
//				printf(",\n");
			json_profile_argument_debug(argumentit,indent+1, true, str);
		}
		g_string_append_printf(str, "\n");
//		printf("\n");
		g_string_append_printf(str, "%*s}", indent*4," ");
//		printf("%*s}", indent*4," ");
		break;

	case render_array:
		if( has_name )
			g_string_append_printf(str, "%*s\"%s\" : [\n", indent*4, " ", argument->argname);
//			printf("%*s\"%s\" : [\n", indent*4, " ", argument->argname);
		else
			g_string_append_printf(str, "[\n");
//			printf("[\n");
		for (argumentit = emu_profile_arguments_first(argument->value.tstruct.arguments); 
			  !emu_profile_arguments_istail(argumentit); 
			  argumentit = emu_profile_arguments_next(argumentit))
		{
			if(argumentit != emu_profile_arguments_first(argument->value.tstruct.arguments))
				g_string_append_printf(str, ",\n");
//				printf(",\n");
			json_profile_argument_debug(argumentit,indent+1, false, str);
		}
		g_string_append_printf(str, "\n");
//		printf("\n");
		g_string_append_printf(str, "%*s]", indent*4, " ");
//		printf("%*s]", indent*4, " ");
		break;

	case render_int:
		if( has_name )
			g_string_append_printf(str, "%*s\"%s\" : \"%i\"", indent*4, " ", argument->argname, argument->value.tint);
//			printf("%*s\"%s\" : \"%i\"", indent*4, " ", argument->argname, argument->value.tint);
		else
			g_string_append_printf(str, "%*s\"%i\"", indent*4, " ", argument->value.tint);
//			printf("%*s\"%i\"", indent*4, " ", argument->value.tint);
		break;

	case render_short:
		if( has_name )
			g_string_append_printf(str, "%*s\"%s\" : \"%i\"", indent*4, " ", argument->argname, argument->value.tshort);
//			printf("%*s\"%s\" : \"%i\"", indent*4, " ", argument->argname, argument->value.tshort);
		else
			g_string_append_printf(str, "%*s\"%i\"", indent*4, " ", argument->value.tshort);
//			printf("%*s\"%i\"", indent*4, " ", argument->value.tshort);
		break;


	case render_string:
		if( has_name )
			g_string_append_printf(str, "%*s\"%s\" : \"%s\"", indent*4, " ", argument->argname, argument->value.tchar);
//			printf("%*s\"%s\" : \"%s\"", indent*4, " ", argument->argname, argument->value.tchar);
		else
			g_string_append_printf(str, "%*s\"%s\"", indent*4, " ", argument->value.tchar);
//			printf("%*s\"%s\"", indent*4, " ", argument->value.tchar);

		break;

	case render_bytea:
		break;

	case render_ptr:
		json_profile_argument_debug(argument->value.tptr.ptr, indent+1, false, str);
		break;

	case render_ip:
		if( has_name )
			g_string_append_printf(str, "%*s\"%s\" : \"%s\"", indent*4, " ", argument->argname, inet_ntoa(*(struct in_addr *)&argument->value.tint));
//			printf("%*s\"%s\" : \"%s\"", indent*4, " ", argument->argname, inet_ntoa(*(struct in_addr *)&argument->value.tint));
		else
			g_string_append_printf(str, "%*s\"%s\"", indent*4, " ", inet_ntoa(*(struct in_addr *)&argument->value.tint));
//			printf("%*s\"%s\"", indent*4, " ", inet_ntoa(*(struct in_addr *)&argument->value.tint));

		break;

	case render_port:
		if( has_name )
			g_string_append_printf(str, "%*s\"%s\" : \"%i\"", indent*4, " ", argument->argname, ntohs((uint16_t)argument->value.tint));
//			printf("%*s\"%s\" : \"%i\"", indent*4, " ", argument->argname, ntohs((uint16_t)argument->value.tint));
		else
			g_string_append_printf(str, "%*s\"%i\"", indent*4, " ", ntohs((uint16_t)argument->value.tint));
//			printf("%*s\"%i\"", indent*4, " ", ntohs((uint16_t)argument->value.tint));

		break;

	case render_none:
		if( has_name )
			g_string_append_printf(str, "%*s\"%s\" : \"\"", indent*4, " ", argument->argname);
//			printf("%*s\"%s\" : \"\"", indent*4, " ", argument->argname);
		else
			g_string_append_printf(str, "%*s\"\"", indent*4, " ");
//			printf("%*s\"\"", indent*4, " ");

		break;
	}
}
void json_profile_function_debug(struct emu_profile_function *function, int indent, GString *str);

void json_profile_debug(struct emu_profile *profile, GString *str)
{
	struct emu_profile_function *function;
	g_string_append_printf(str, "[\n");
//	printf("[\n");
	for (function = emu_profile_functions_first(profile->functions); !emu_profile_functions_istail(function); function = emu_profile_functions_next(function))
	{
		if( function !=  emu_profile_functions_first(profile->functions))
//			printf(",\n");
			g_string_append_printf(str, ",\n");
		json_profile_function_debug(function, 1, str);

	}
//	printf("\n");
	g_string_append_printf(str, "\n");
//	printf("]");
	g_string_append_printf(str, "]");
}

void json_profile_function_debug(struct emu_profile_function *function, int indent, GString *str)
{

	g_string_append_printf(str, "%*s{\n", indent*4, " ");
//	printf("%*s{\n", indent*4, " ");
	indent++;
	g_string_append_printf(str, "%*s\"call\": \"%s\",\n", indent*4, " ", function->fnname);
//	printf("%*s\"call\": \"%s\",\n", indent*4, " ", function->fnname);
	g_string_append_printf(str, "%*s\"args\" : [ \n", indent*4, " ");
//	printf("%*s\"args\" : [ \n", indent*4, " ");
	struct emu_profile_argument *argument;
	for (argument = emu_profile_arguments_first(function->arguments); 
		  !emu_profile_arguments_istail(argument); 
		  argument = emu_profile_arguments_next(argument))
	{
		if(argument != emu_profile_arguments_first(function->arguments))
			g_string_append_printf(str, ",\n");
//			printf(",\n");
		json_profile_argument_debug(argument,indent+1, false, str);
	}
	g_string_append_printf(str, "\n");
//	printf("\n");
	
	g_string_append_printf(str, "%*s],\n", indent*4, " ");
//	printf("%*s],\n", indent*4, " ");
	switch (function->return_value->render)
	{
	case render_none:
		g_string_append_printf(str, "%*s\"return\": \"void\"\n", indent*4, " ");
//		printf("%*s\"return\": \"void\"\n", indent*4, " ");
		break;
	case render_int:
		g_string_append_printf(str, "%*s\"return\":  \"%i\"\n", indent*4, " ", function->return_value->value.tint);
//		printf("%*s\"return\":  \"%i\"\n", indent*4, " ", function->return_value->value.tint);
		break;

	case render_ptr:
		g_string_append_printf(str, "%*s\"return\" : \"0x%08x\"\n", indent*4, " ", function->return_value->value.tptr.addr);
//		printf("%*s\"return\" : \"0x%08x\"\n", indent*4, " ", function->return_value->value.tptr.addr);
		break;
	default:
//		printf("}");
		break;

	}
	indent--;
	g_string_append_printf(str, "%*s}", indent*4, " ");
//	printf("%*s}", indent*4, " ");

}

void profile(struct connection *con, void *data, unsigned int size, unsigned int offset)
{
	struct emu *e = emu_new();
	struct emu_env *env = emu_env_new(e);
	env->profile = emu_profile_new();

//	struct emu_cpu *cpu = emu_cpu_get(e);
	struct emu_memory *mem = emu_memory_get(e);
	emu_cpu_reg32_set(emu_cpu_get(e), esp, 0x0012fe98);

	emu_memory_write_block(mem, CODE_OFFSET, data,  size);
	emu_cpu_eip_set(emu_cpu_get(e), CODE_OFFSET + offset);
	run(e, env);
	GString *str = g_string_new(NULL);
	json_profile_debug(env->profile, str);
	printf("%s", str->str);
	struct incident *i = incident_new("dionaea.module.emu.profile");
	incident_value_string_set(i, "profile", str);
	incident_value_ptr_set(i, "con", (uintptr_t)con);
	connection_ref(con);
	GAsyncQueue *aq = g_async_queue_ref(g_dionaea->threads->cmds);
	g_async_queue_push(aq, async_cmd_new(async_incident_report, i));
	g_async_queue_unref(aq);
	ev_async_send(g_dionaea->loop, &g_dionaea->threads->trigger);

	emu_env_free(env);
	emu_free(e);
}
