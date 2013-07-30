/*!
 * \file changesets.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>, Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief Structure for representing IXFR/DDNS changeset and its API.
 *
 * \addtogroup xfr
 * @{
 */
/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#ifndef _KNOT_CHANGESETS_H_
#define _KNOT_CHANGESETS_H_

#include "rrset.h"
#include "zone/node.h"
#include "common/lists.h"
#include "common/mempattern.h"

/*----------------------------------------------------------------------------*/

/*! \brief Changeset flags, stored as first 4 bytes in serialized changeset. */
typedef enum {
	KNOT_CHANGESET_TYPE_IXFR = 1 << 0,
	KNOT_CHANGESET_TYPE_DDNS = 1 << 1
} knot_changeset_flag_t;


/*! \brief One changeset received from wire, with parsed RRs. */
typedef struct knot_changeset {
	node n; /*!< List node. */
	mm_ctx_t mem_ctx; /*!< Memory context - pool allocator. */
	knot_rrset_t *soa_from; /*!< Start SOA. */
	list remove; /*!< List of RRs to remove. */
	knot_rrset_t *soa_to; /*!< Destination SOA. */
	list add; /*!< List of RRs to add. */
	uint8_t *data; /*!< Serialized changeset. */
	size_t size; /*!< Size of serialized changeset. */
	uint32_t serial_from; /*!< SOA start serial. */
	uint32_t serial_to; /*!< SOA destination serial. */
	uint32_t flags; /*!< DDNS / IXFR flags. */
} knot_changeset_t;

/*----------------------------------------------------------------------------*/

/*! \brief Wrapper BIRD lists. Storing: RRSet. */
typedef struct knot_rr_ln {
	node n; /*!< List node. */
	knot_rrset_t *rr; /*!< Actual usable data. */
} knot_rr_ln_t;

/*! \brief Wrapper BIRD lists. Storing: Node. */
typedef struct knot_node_ln {
	node n; /*!< List node. */
	knot_node_t *node; /*!< Actual usable data. */
} knot_node_ln_t;

/*! \brief Partial changes done to zones - used for update/transfer rollback. */
typedef struct {
	/*!
	 * Memory context. We need a pool allocator since there is a possibility
	 * of many changes in one transfer/update.
	 */
	mm_ctx_t mem_ctx;
	/*!
	 * Deleted after successful update.
	 */
	list old_rrsets;
	/*!
	 * Deleted after failed update.
	 */
	list new_rrsets;
	/*!
	 * Deleted (without contents) after successful update.
	 */
	list old_nodes;
	/*!
	 * Deleted (without contents) after successful update.
	 */
	list old_nsec3;
} knot_changes_t;

/*----------------------------------------------------------------------------*/

/*!
 * \brief Changeset structure (changes recieved by slave server between two
 *        serial numbers.
 */
typedef struct {
	mm_ctx_t mmc_chs; /*!< Memory context for creating changesets */
	mm_ctx_t mmc_rr; /*!< Memory context for creating RRs in changesets */
	list sets; /*!< List of changesets. */
	size_t count; /*!< Changeset count. */
	knot_rrset_t *first_soa; /*!< First received SOA. */
	uint32_t flags; /*!< DDNS / IXFR flags. */
	knot_changes_t *changes; /*!< Partial changes. */
} knot_changesets_t;

/*----------------------------------------------------------------------------*/

typedef enum {
	KNOT_CHANGESET_ADD,
	KNOT_CHANGESET_REMOVE
} knot_changeset_part_t;

typedef enum {
	KNOT_CHANGES_OLD,
	KNOT_CHANGES_NEW,
	KNOT_CHANGES_NORMAL_NODE,
	KNOT_CHANGES_NSEC3_NODE
} knot_changes_part_t;

/*----------------------------------------------------------------------------*/

/*!
 * \brief Inits changesets structure. Memory allocators are created and have to
 *        be freed using knot_changesets_free().
 *
 * \param changesets Double pointer to changesets structure.
 * \param flags IXFR / DDNS flag.
 *
 * \retval KNOT_EOK on success.
 * \retval Error code on failure.
 */
int knot_changesets_init(knot_changesets_t **changesets,
                         uint32_t flags);

/*!
 * \brief Creates changesets structure. Memory allocators are created
 *        and have to be freed using knot_changesets_free().
 *
 * \param flags IXFR / DDNS flag.
 *
 * \retval Created structure on success.
 * \retval NULL on failure.
 */
knot_changesets_t *knot_changesets_create(uint32_t flags);

/*!
 * \brief Creates new changeset structure and returns it to caller.
 *        The structure is also connected to a list of changesets.
 *
 * \param ch Changesets structure to create a new changeset in.
 *
 * \retval Created structure on success.
 * \retval NULL on failure.
 */
knot_changeset_t *knot_changesets_create_changeset(knot_changesets_t *ch);

/*!
 * \brief Gets last changesets from from structure's list.
 *
 * \param ch Changesets structure to get a last changeset from.
 *
 * \retval Last changeset on success.
 * \retval NULL on failure.
 */
knot_changeset_t *knot_changesets_get_last(const knot_changesets_t *ch);

/*!
 * \brief Add RRSet to changeset. RRSet is either inserted to 'add' or to
 *        'remove' list. Will *not* try to merge with previous RRSets.
 *
 * \param chgs Changeset to add RRSet into.
 * \param rrset RRSet to be added.
 * \param part Add to 'add' or 'remove'?
 *
 * \retval KNOT_EOK on success.
 * \retval Error code on failure.
 */
int knot_changeset_add_rrset(knot_changeset_t *chgs,
                             knot_rrset_t *rrset, knot_changeset_part_t part);

/*!
 * \brief Add RRSet to changeset. RRSet is either inserted to 'add' or to
 *        'remove' list. *Will* try to merge with previous RRSets.
 *
 * \param chgs Changeset to add RRSet into.
 * \param rrset RRSet to be added.
 * \param part Add to 'add' or 'remove'?
 *
 * \retval KNOT_EOK on success.
 * \retval Error code on failure.
 */
int knot_changeset_add_rr(knot_changeset_t *chgs,
                          knot_rrset_t *rrset, knot_changeset_part_t part);

/*!
 * \brief Adds a source/destination SOA RRSet to changeset.
 *
 * \param changeset Changeset to store SOA to.
 * \param soa SOA RRSet to be stored to changeset.
 * \param part To which part we store SOA (from = REMOVE, add = TO)
 */
void knot_changeset_add_soa(knot_changeset_t *changeset, knot_rrset_t *soa,
                           knot_changeset_part_t part);

/*!
 * \brief Checks whether changeset is empty.
 *
 * \param changeset Changeset to be checked.
 *
 * \retval 1 if changeset is empty.
 * \retval 0 if changeset is not empty.
 */
int knot_changeset_is_empty(const knot_changeset_t *changeset);

/*!
 * \brief Frees the 'changesets' structure, including its memory allocators.
 *
 * \param changesets Double pointer to changesets structure to be freed.
 */
void knot_changesets_free(knot_changesets_t **changesets);

/*!
 * \brief Add RRSet to changes structure.
 *        RRSet is either inserted to 'old' or to 'new' list.
 *
 * \param chgs Change to add RRSet into.
 * \param rrset RRSet to be added.
 * \param part Add to 'old' or 'new'?
 *
 * \retval KNOT_EOK on success.
 * \retval Error code on failure.
 */
int knot_changes_add_rrset(knot_changes_t *ch, knot_rrset_t *rrset,
                           knot_changes_part_t part);

/*!
 * \brief Add Node to changes structure.
          Node is either inserted to 'normal' or to 'NSEC3' list.
 *
 * \param chgs Change to add node into.
 * \param node RRSet to be added.
 * \param part Add to 'normal' or 'NSEC3'?
 *
 * \retval KNOT_EOK on success.
 * \retval Error code on failure.
 */
int knot_changes_add_node(knot_changes_t *ch, knot_node_t *kn_node,
                          knot_changes_part_t part);

/*!
 * \brief Frees changes structure, including its memory allocator.
 *
 * \param changes Double pointer of changes structure to be freed.
 */
void knot_changes_free(knot_changes_t **changes);

#endif /* _KNOT_CHANGESETS_H_ */

/*! @} */
