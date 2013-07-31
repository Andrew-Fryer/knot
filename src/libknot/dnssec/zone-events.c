/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <assert.h>
#include "knot/conf/conf.h"
#include "knot/server/zones.h"
#include "libknot/dnssec/zone-events.h"
#include "libknot/dnssec/zone-nsec.h"
#include "libknot/dnssec/zone-sign.h"
#include "libknot/zone/zone.h"

int knot_dnssec_zone_load(knot_zone_t *zone)
{
	conf_zone_t *zone_config = ((zonedata_t *)knot_zone_data(zone))->conf;
	knot_changesets_t *changesets = NULL;
	int result = KNOT_EOK;

	if (!zone_config->dnssec_enable) {
//		log_server_warning("DNSSEC not enabled for '%s'.\n", zone_name);
		return KNOT_EOK;
	}

	result = knot_changeset_allocate(&changesets, KNOT_CHANGESET_TYPE_DNSSEC);
	if (result != KNOT_EOK) {
//		log_server_error("Cannot create new changeset.\n");
		return result;
	}

	knot_changeset_t *changeset = changesets->sets;
	assert(changeset);
	changesets->count = 1;

	// generate NSEC records

	result = knot_zone_create_nsec_chain(zone->contents, changeset);
	if (result != KNOT_EOK) {
//		log_server_error("Could not create NSEC chain for '%s' (%s).\n",
//				 zone_name, knot_strerror(result));
		knot_free_changesets(&changesets);
		return result;
	}

	// add missing signatures

	rcu_read_lock();
	char *keydir = strdup(conf()->dnssec_keydir);
	rcu_read_unlock();

	result = knot_zone_sign(zone->contents, keydir, changeset);
	free(keydir);
	if (result != KNOT_EOK) {
//		log_server_error("Could not resing zone '%s' (%s).\n",
//				 zone_name, knot_strerror(result));
		knot_free_changesets(&changesets);
		return result;
	}

	// update SOA if there are any changes

	log_server_info("changeset add %zu remove %zu\n", changeset->add_count, changeset->remove_count);

	if (changeset->add_count == 0 && changeset->remove_count == 0) {
//		log_server_info("No changes performed.\n");
		knot_free_changesets(&changesets);
		return KNOT_EOK;
	}

	// dump changeset

//	{
//	for (size_t i = 0; i < changeset->add_count; i++) {
//		knot_rrset_t *rrset = changeset->add[i];
//		char *name = knot_dname_to_str(rrset->owner);
//
//		log_server_info("[add %dx] %s type %d class %d ttl %d\n",
//				rrset->rdata_count,
//				name, rrset->type, rrset->rclass, rrset->ttl);
//	}
//	for (size_t i = 0; i < changeset->remove_count; i++) {
//		knot_rrset_t *rrset = changeset->remove[i];
//		char *name = knot_dname_to_str(rrset->owner);
//
//		log_server_info("[remove %dx] %s type %d class %d ttl %d\n",
//				rrset->rdata_count,
//				name, rrset->type, rrset->rclass, rrset->ttl);
//	}
//	}

	result = knot_zone_sign_update_soa(zone->contents, changeset);
	if (result != KNOT_EOK) {
//		log_server_error("Cannot update SOA record (%s).\n",
//				 knot_strerror(result));
		knot_free_changesets(&changesets);
		return result;
	}

	// apply changeset

	knot_zone_contents_t *new_contents = NULL;
	result = zones_store_and_apply_chgsets(changesets, zone, &new_contents,
					       "DNSSEC", XFR_TYPE_UPDATE);
	if (result != KNOT_EOK) {
//		log_server_error("Cannot apply changeset (%s).\n",
//				 knot_strerror(result));
		knot_free_changesets(&changesets);
		return result;
	}

	// changesets are freed by zones_store_and_apply_chgsets()

	return KNOT_EOK;
}
