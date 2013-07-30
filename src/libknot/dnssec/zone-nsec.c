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
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

#include "common/base32hex.c"
#include "common/descriptor.h"
#include "libknot/dnssec/nsec-bitmap.h"
#include "libknot/dnssec/nsec3.h"
#include "libknot/dnssec/zone-nsec.h"
#include "libknot/util/utils.h"
#include "libknot/zone/zone-contents.h"

/* - NSEC chain iteration -------------------------------------------------- */

typedef int (*chain_iterate_cb)(knot_node_t *, knot_node_t *, void *);

/*!
 * \brief Call a function for each piece of the chain formed by sorted nodes.
 *
 * \note If the callback function returns anything other than KNOT_EOK, the
 *       iteration is terminated and the error code is propagated.
 *
 * \param nodes     Zone nodes.
 * \param callback  Callback function.
 * \param data      Custom data supplied to the callback function.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int chain_iterate(knot_zone_tree_t *nodes, chain_iterate_cb callback,
                         void *data)
{
	assert(nodes);
	assert(callback);

	bool sorted = true;
	hattrie_iter_t *it = hattrie_iter_begin(nodes, sorted);

	if (!it)
		return KNOT_ENOMEM;

	if (hattrie_iter_finished(it))
		return KNOT_EINVAL;

	knot_node_t *first = (knot_node_t *)*hattrie_iter_val(it);
	knot_node_t *previous = first;
	knot_node_t *current = first;
	hattrie_iter_next(it);

	while (!hattrie_iter_finished(it)) {
		current = (knot_node_t *)*hattrie_iter_val(it);

		int result = callback(previous, current, data);
		if (result != KNOT_EOK) {
			hattrie_iter_free(it);
			return result;
		}

		previous = current;
		hattrie_iter_next(it);
	}

	hattrie_iter_free(it);

	return callback(current, first, data);
}

/* - RRSIGs recyclation ---------------------------------------------------- */

/*!
 * \brief Perform some basic checks that the node is valid NSEC3 node.
 */
inline static bool valid_nsec3_node(const knot_node_t *node)
{
	if (node->rrset_count != 1)
		return false;

	if (node->rrset_tree[0]->type != KNOT_RRTYPE_NSEC3)
		return false;

	if (node->rrset_tree[0]->rdata_count != 1)
		return false;

	return true;
}

/*!
 * \brief Check if two NSEC3 nodes contain equal RDATA.
 *
 * \note Much simpler than 'knot_rrset_rdata_equal'.
 */
static bool are_nsec3_nodes_equal(const knot_node_t *a, const knot_node_t *b)
{
	assert(valid_nsec3_node(a));
	assert(valid_nsec3_node(b));

	knot_rrset_t *a_rrset = a->rrset_tree[0];
	knot_rrset_t *b_rrset = b->rrset_tree[0];

	uint32_t rdata_size = rrset_rdata_item_size(a_rrset, 0);
	if (rdata_size != rrset_rdata_item_size(b_rrset, 0))
		return false;

	uint8_t *a_rdata = knot_rrset_get_rdata(a_rrset, 0);
	uint8_t *b_rdata = knot_rrset_get_rdata(b_rrset, 0);

	return memcmp(a_rdata, b_rdata, (size_t)rdata_size) == 0;
}

/*!
 * \brief Move NSEC3 signatures from the one node to the second one.
 */
static void move_signatures(knot_node_t *from, knot_node_t *to)
{
	assert(valid_nsec3_node(from));
	assert(valid_nsec3_node(to));

	knot_rrset_t *from_rrset = from->rrset_tree[0];
	knot_rrset_t *to_rrset = to->rrset_tree[0];

	assert(to_rrset->rrsigs == NULL);

	to_rrset->rrsigs = from_rrset->rrsigs;
	from_rrset->rrsigs = NULL;
}

/*!
 * \brief Recycle NSEC3 signatatures by moving them from one tree to another.
 *
 * When the zone is loaded, new NSEC3 tree is constructed as the hashes have
 * to be recomputed to be able to connect regular nodes with NSEC3 nodes. Any
 * existing signatures from the NSEC3 tree are the moved to the new tree, if
 * the NSEC3 nodes are matching. The old NSEC3 tree can be then freed.
 */
static int recycle_signatures(knot_zone_tree_t *from, knot_zone_tree_t *to)
{
	assert(to);

	if (!from)
		return KNOT_EINVAL;

	bool sorted = false;
	hattrie_iter_t *it = hattrie_iter_begin(from, sorted);

	for (/* NOP */; !hattrie_iter_finished(it); hattrie_iter_next(it)) {
		knot_node_t *node_from = (knot_node_t *)*hattrie_iter_val(it);
		knot_node_t *node_to = NULL;

		knot_zone_tree_get(to, node_from->owner, &node_to);
		if (node_to == NULL)
			continue;

		if (!are_nsec3_nodes_equal(node_from, node_to))
			continue;

		move_signatures(node_from, node_to);
	}

	hattrie_iter_free(it);

	return KNOT_EOK;
}

/* - NSEC nodes construction ----------------------------------------------- */

/*!
 * \brief Create NSEC RR set.
 *
 * \param owner     Record owner.
 * \param next      Owner of the immeditatelly following node.
 * \param rr_types  Bitmap with RR types of the owning node.
 * \param ttl       Record TTL.
 *
 * \return NSEC RR set, NULL on error.
 */
static knot_rrset_t *create_nsec_rrset(knot_dname_t *owner, knot_dname_t *next,
				       const bitmap_t *rr_types, uint32_t ttl)
{
	knot_rrset_t *rrset;
	rrset = knot_rrset_new(owner, KNOT_RRTYPE_NSEC, KNOT_CLASS_IN, ttl);
	if (!rrset)
		return NULL;

	size_t rdata_size = sizeof(knot_dname_t *) + bitmap_size(rr_types);
	uint8_t *rdata = knot_rrset_create_rdata(rrset, rdata_size);
	if (!rdata) {
		knot_rrset_free(&rrset);
		return NULL;
	}

	knot_dname_retain(next);
	memcpy(rdata, &next, sizeof(knot_dname_t *));
	bitmap_write(rr_types, rdata + sizeof(knot_dname_t *));

	return rrset;
}

/*!
 * \brief Connect two nodes by adding a NSEC RR set into the first node.
 *
 * Callback function, signature chain_iterate_cb.
 *
 * \param a     First node.
 * \param b     Second node (immediate follower of a).
 * \param data  Pointer to uint32_t variable holding TTL for the new NSEC node.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int connect_nsec_nodes(knot_node_t *a, knot_node_t *b, void *data)
{
	uint32_t ttl = *(uint32_t *)data;

	bitmap_t rr_types = { 0 };
	bitmap_add_rrset(&rr_types, a->rrset_tree, a->rrset_count);
	bitmap_add_type(&rr_types, KNOT_RRTYPE_NSEC);
	bitmap_add_type(&rr_types, KNOT_RRTYPE_RRSIG);

	knot_rrset_t *nsec = create_nsec_rrset(a->owner, b->owner, &rr_types, ttl);
	if (!nsec)
		return KNOT_ENOMEM;

	return knot_node_add_rrset_no_merge(a, nsec);
}

/*!
 * \brief Add NSEC records into the zone.
 *
 * \note Expects that no NSEC records are present in the zone.
 *
 * \param zone Zone.
 * \param ttl TTL for created NSEC records.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int create_nsec_chain(knot_zone_contents_t *zone, uint32_t ttl)
{
	assert(zone);
	assert(zone->nodes);

	return chain_iterate(zone->nodes, connect_nsec_nodes, &ttl);
}


/* - NSEC3 names conversion ------------------------------------------------ */

/*!
 * \brief Create NSEC3 owner name from hash and zone apex.
 *
 * \param hash       Raw hash.
 * \param hash_size  Size of the hash.
 * \param apex       Zone apex.
 * \param apex_size  Size of the zone apex.
 *
 * \return NSEC3 owner name, NULL in case of error.
 */
static knot_dname_t *nsec3_hash_to_dname(const uint8_t *hash, size_t hash_size,
					 const char *apex, size_t apex_size)
{
	char name[KNOT_DNAME_MAX_LENGTH];
	size_t endp;

	endp = base32hex_encode(hash, hash_size, (uint8_t *)name, sizeof(name));
	if (endp <= 0)
		return NULL;

	name[endp] = '.';
	endp += 1;

	memcpy(name + endp, apex, apex_size);
	endp += apex_size;

	knot_dname_t *dname = knot_dname_new_from_str(name, endp, NULL);
	knot_dname_to_lower(dname);

	return dname;
}

/*!
 * \brief Create NSEC3 owner name from regular owner name.
 *
 * \param owner      Node owner name.
 * \param params     Params for NSEC3 hashing function.
 * \param apex       Apex size.
 * \param apex_size  Size of the zone apex.
 *
 * \return NSEC3 owner name, NULL in case of error.
 */
static knot_dname_t *create_nsec3_owner(const knot_dname_t *owner,
                                        const knot_nsec3_params_t *params,
                                        const char *apex, size_t apex_size)
{
	uint8_t *name = owner->name;
	size_t name_size = owner->size;
	uint8_t *hash = NULL;
	size_t hash_size = 0;

	if (knot_nsec3_hash(params, name, name_size, &hash, &hash_size) != KNOT_EOK)
		return NULL;

	knot_dname_t *result = nsec3_hash_to_dname(hash, hash_size, apex, apex_size);
	free(hash);

	return result;
}

/* - NSEC3 nodes construction ---------------------------------------------- */

/*!
 * \brief Get NSEC3 RDATA size.
 */
static size_t nsec3_rdata_size(const knot_nsec3_params_t *params,
                               const bitmap_t *rr_types)
{
	return 6 + params->salt_length + KNOT_NSEC3_HASH_LENGTH
	       + bitmap_size(rr_types);
}

/*!
 * \brief Fill NSEC3 RDATA.
 *
 * \note Content of next hash field is not changed.
 */
static void nsec3_fill_rdata(uint8_t *rdata, const knot_nsec3_params_t *params,
                             const bitmap_t *rr_types, uint32_t ttl)
{
	*rdata = params->algorithm;                       // hash algorithm
	rdata += 1;
	*rdata = 0;                                       // flags
	rdata += 1;
	knot_wire_write_u16(rdata, params->iterations);   // iterations
	rdata += 2;
	*rdata = params->salt_length;                     // salt length
	rdata += 1;
	memcpy(rdata, params->salt, params->salt_length); // salt
	rdata += params->salt_length;
	*rdata = KNOT_NSEC3_HASH_LENGTH;                  // hash length
	rdata += 1;
	/*memset(rdata, '\0', KNOT_NSEC3_HASH_LENGTH);*/  // hash (unknown)
	rdata += KNOT_NSEC3_HASH_LENGTH;
	bitmap_write(rr_types, rdata);                    // RR types bit map
}

/*!
 * \brief Create NSEC3 RR set.
 */
static knot_rrset_t *create_nsec3_rrset(knot_dname_t *owner,
                                        const knot_nsec3_params_t *params,
                                        const bitmap_t *rr_types,
                                        uint32_t ttl)
{
	knot_rrset_t *rrset;
	rrset = knot_rrset_new(owner, KNOT_RRTYPE_NSEC3, KNOT_CLASS_IN, ttl);
	if (!rrset)
		return NULL;

	size_t rdata_size = nsec3_rdata_size(params, rr_types);
	uint8_t *rdata = knot_rrset_create_rdata(rrset, rdata_size);
	if (!rdata) {
		knot_rrset_free(&rrset);
		return NULL;
	}

	nsec3_fill_rdata(rdata, params, rr_types, ttl);

	return rrset;
}

/*!
 * \brief Create NSEC3 node and add it into the zone.
 */
static knot_node_t *create_nsec3_node(knot_dname_t *owner,
                                      const knot_nsec3_params_t *nsec3_params,
                                      knot_node_t *apex_node,
                                      const bitmap_t *rr_types,
                                      uint32_t ttl)
{
	uint8_t flags = 0;
	knot_node_t *new_node = knot_node_new(owner, apex_node, flags);
	if (!new_node)
		return NULL;

	knot_rrset_t *nsec3_rrset;
	nsec3_rrset = create_nsec3_rrset(owner, nsec3_params, rr_types, ttl);
	if (!nsec3_rrset) {
		knot_node_free(&new_node);
		return NULL;
	}

	if (knot_node_add_rrset_no_merge(new_node, nsec3_rrset) != KNOT_EOK) {
		knot_rrset_free(&nsec3_rrset);
		knot_node_free(&new_node);
		return NULL;
	}

	return new_node;
}

/*!
 * \brief Get position of hash field in NSEC3 rdata.
 */
static uint8_t *nsec3_rdata_hash(uint8_t *rdata)
{
	rdata += 4;           // algorithm, flags, iterations
	rdata += 1 + *rdata;  // salt length, salt
	assert(*rdata == KNOT_NSEC3_HASH_LENGTH);
	rdata += 1;           // hash length

	return rdata;
}

/*!
 * \brief Connect two nodes by filling 'hash' field of NSEC3 RDATA of the node.
 *
 * \param a     First node.
 * \param b     Second node (immediate follower of a).
 * \param data  Unused parameter.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int connect_nsec3_nodes(knot_node_t *a, knot_node_t *b, void *data)
{
	UNUSED(data);
	assert(a);
	assert(b);

	assert(a->rrset_count == 1);
	uint8_t *rdata_hash = nsec3_rdata_hash(a->rrset_tree[0]->rdata);

	uint8_t *b32_hash = (uint8_t *)knot_dname_to_str(b->owner);
	if (!b32_hash)
		return KNOT_ENOMEM;

	int written = base32hex_decode(b32_hash, KNOT_NSEC3_HASH_B32_LENGTH,
	                               rdata_hash, KNOT_NSEC3_HASH_LENGTH);

	free(b32_hash);

	if (written != KNOT_NSEC3_HASH_LENGTH)
		return KNOT_EINVAL;

	return KNOT_EOK;
}

/*!
 * \brief Get zone apex as a string.
 */
static bool get_zone_apex_str(knot_zone_contents_t *zone,
			      char **apex, size_t *apex_size)
{
	assert(zone);
	assert(zone->apex);
	assert(apex);
	assert(apex_size);

	*apex = knot_dname_to_str(zone->apex->owner);
	if (!*apex)
		return false;

	*apex_size = strlen(*apex);

	return true;
}

/*!
 * \brief Create new NSEC3 node for given regular node.
 *
 * \note Parameters 'apex' and 'apex_size' are added for performace reasons.
 *
 * \param node       Node for which the NSEC3 node is created.
 * \param apex_node  Zone apex node.
 * \param apex       Zone apex.
 * \param apex_size  Size fo zone apex.
 * \param params     NSEC3 hash function parameters.
 * \param ttl        TTL of the new NSEC3 node.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static knot_node_t *create_nsec3_node_for_node(knot_node_t *node,
                                               knot_node_t *apex_node,
                                               char *apex, size_t apex_size,
                                               const knot_nsec3_params_t *params,
                                               uint32_t ttl)
{
	knot_dname_t *nsec3_owner;
	nsec3_owner = create_nsec3_owner(node->owner, params, apex, apex_size);
	if (!nsec3_owner)
		return NULL;

	bitmap_t rr_types = { 0 };
	bitmap_add_rrset(&rr_types, node->rrset_tree, node->rrset_count);
	if (node->rrset_count > 0)
		bitmap_add_type(&rr_types, KNOT_RRTYPE_RRSIG);

	knot_node_t *nsec3_node;
	nsec3_node = create_nsec3_node(nsec3_owner, params, apex_node, &rr_types, ttl);
	knot_dname_release(nsec3_owner);

	return nsec3_node;
}

/*!
 * \brief Create NSEC3 node for each regular node in the zone.
 *
 * \param zone         Zone.
 * \param ttl          TTL for the created NSEC records.
 * \param nsec3_nodes  Tree whereto new NSEC3 nodes will be added.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int create_nsec3_nodes(knot_zone_contents_t *zone, uint32_t ttl,
                              knot_zone_tree_t *nsec3_nodes)
{
	const knot_nsec3_params_t *params = &zone->nsec3_params;

	char *apex = NULL;
	size_t apex_size;
	if (!get_zone_apex_str(zone, &apex, &apex_size))
		return KNOT_ENOMEM;

	int result = KNOT_EOK;

	int sorted = false;
	hattrie_iter_t *it = hattrie_iter_begin(zone->nodes, sorted);
	while (!hattrie_iter_finished(it)) {
		knot_node_t *node = (knot_node_t *)*hattrie_iter_val(it);

		knot_node_t *nsec3_node;
		nsec3_node = create_nsec3_node_for_node(node, zone->apex, apex,
		                                        apex_size, params, ttl);
		if (!nsec3_node) {
			result = KNOT_ENOMEM;
			break;
		}

		result = knot_zone_tree_insert(nsec3_nodes, nsec3_node);
		if (result != KNOT_EOK)
			break;

		node->nsec3_node = nsec3_node;

		hattrie_iter_next(it);
	}

	hattrie_iter_free(it);
	free(apex);

	return result;
}

/*!
 * \brief Create new NSEC3 chain and add it into the zone.
 */
static int create_nsec3_chain(knot_zone_contents_t *zone, uint32_t ttl)
{
	assert(zone);

	int result;

	knot_zone_tree_t *nsec3_nodes = knot_zone_tree_create();
	if (!nsec3_nodes)
		return KNOT_ENOMEM;

	result = create_nsec3_nodes(zone, ttl, nsec3_nodes);
	if (result != KNOT_EOK) {
		knot_zone_tree_free(&nsec3_nodes);
		return result;
	}

	result = chain_iterate(nsec3_nodes, connect_nsec3_nodes, NULL);
	if (result != KNOT_EOK) {
		knot_zone_tree_free(&nsec3_nodes);
		return result;
	}

	/*
	 * Signatures recyclation:
	 *
	 * TODO: rewrite, when we have RDATA reference counting
	 *
	 * 1. create shallow copy of the old NSEC3 tree
	 * 2. steal signatures by setting the pointer in the new tree and
	 *    setting the original pointer in the copied tree to NULL
	 * 3. set new NSEC3 tree in the zone
	 * 4. deep free the copied tree, shallow free the old tree
	 */

	knot_zone_tree_t *copy;
	result = knot_zone_tree_shallow_copy(zone->nsec3_nodes, &copy);
	if (result != KNOT_EOK) {
		knot_zone_tree_free(&nsec3_nodes);
		return result;
	}

	result = recycle_signatures(copy, nsec3_nodes);
	if (result != KNOT_EOK) {
		knot_zone_tree_free(&nsec3_nodes);
		knot_zone_tree_free(&copy);
		return result;
	}

	knot_zone_tree_deep_free(&copy);
	knot_zone_tree_free(&zone->nsec3_nodes);
	zone->nsec3_nodes = nsec3_nodes;

	return KNOT_EOK;
}

/* - helper functions ------------------------------------------------------ */

/*!
 * Check if NSEC3 is enabled for the given zone.
 */
static bool is_nsec3_enabled(const knot_zone_contents_t *zone)
{
	return zone->nsec3_params.salt_length > 0;
}

/*!
 * \brief Get minimum TTL from zone SOA.
 * \note Value should be used for NSEC records.
 */
static bool get_zone_soa_min_ttl(const knot_zone_contents_t *zone, uint32_t *ttl)
{
	assert(zone);
	assert(zone->apex);
	assert(ttl);

	knot_node_t *apex = zone->apex;
	knot_rrset_t *soa = knot_node_get_rrset(apex, KNOT_RRTYPE_SOA);
	if (!soa)
		return false;

	uint32_t result =  knot_rrset_rdata_soa_minimum(soa);
	if (result == 0)
		return false;

	*ttl = result;
	return true;
}

/* - public API ------------------------------------------------------------ */

/*!
 * \brief Create NSEC or NSEC3 chain in the zone.
 */
int knot_zone_create_nsec_chain(knot_zone_contents_t *zone)
{
	if (!zone)
		return KNOT_EINVAL;

	uint32_t nsec_ttl = 0;
	if (!get_zone_soa_min_ttl(zone, &nsec_ttl))
		return KNOT_ERROR;

	int result;
	if (is_nsec3_enabled(zone))
		result = create_nsec3_chain(zone, nsec_ttl);
	else
		result = create_nsec_chain(zone, nsec_ttl);

	if (result != KNOT_EOK)
		return result;

	return knot_zone_contents_adjust(zone, NULL, NULL, 0);
}

/*!
 * \brief Connect regular and NSEC3 nodes in the zone.
 */
int knot_zone_connect_nsec_nodes(knot_zone_contents_t *zone)
{
	if (!zone)
		return KNOT_EINVAL;

	if (!is_nsec3_enabled(zone))
		return KNOT_EOK;

	char *apex;
	size_t apex_size;
	if (!get_zone_apex_str(zone, &apex, &apex_size))
		return KNOT_ENOMEM;

	bool sorted = false;
	hattrie_iter_t *it = hattrie_iter_begin(zone->nodes, sorted);
	if (!it) {
		free(apex);
		return KNOT_ENOMEM;
	}

	int result = KNOT_EOK;

	while (!hattrie_iter_finished(it)) {
		knot_node_t *node = (knot_node_t *)*hattrie_iter_val(it);

		knot_dname_t *nsec3_name;
		nsec3_name = create_nsec3_owner(node->owner, &zone->nsec3_params, apex, apex_size);
		if (!nsec3_name) {
			result = KNOT_ENOMEM;
			break;
		}

		knot_node_t *nsec3_node = NULL;
		result = knot_zone_tree_get(zone->nsec3_nodes, nsec3_name, &nsec3_node);
		if (result != KNOT_EOK)
			break;

		if (nsec3_node != NULL)
			node->nsec3_node = nsec3_node;

		knot_dname_release(nsec3_name);
		hattrie_iter_next(it);
	}

	free(apex);
	hattrie_iter_free(it);

	return result;
}
