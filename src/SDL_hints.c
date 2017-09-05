/*
  Simple DirectMedia Layer
  Copyright (C) 1997-2017 Sam Lantinga <slouken@libsdl.org>

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.
*/
#include "./SDL_internal.h"

#include "SDL_hints.h"
#include "SDL_error.h"


/* Assuming there aren't many hints set and they aren't being queried in
   critical performance paths, we'll just use linked lists here.
 */
typedef struct SDL_HintWatch {
    SDL_HintCallback callback;
    void *userdata;
    struct SDL_HintWatch *next;
} SDL_HintWatch;

typedef struct SDL_Hint {
    char *name;
    char *value;
    SDL_HintPriority priority;
    SDL_HintWatch *callbacks;
    struct SDL_Hint *next;
} SDL_Hint;

static SDL_Hint *SDL_hints;

SDL_bool
SDL_SetHintWithPriority(const char *name, const char *value,
                        SDL_HintPriority priority)
{
    const char *env;
    SDL_Hint *hint;
    SDL_HintWatch *entry;

    if (!name || !value) {
        return SDL_FALSE;
    }

    env = SDL_getenv(name);
    if (env && priority < SDL_HINT_OVERRIDE) {
        return SDL_FALSE;
    }

    for (hint = SDL_hints; hint; hint = hint->next) {
        if (SDL_strcmp(name, hint->name) == 0) {
            if (priority < hint->priority) {
                return SDL_FALSE;
            }
            if (!hint->value || !value || SDL_strcmp(hint->value, value) != 0) {
                for (entry = hint->callbacks; entry; ) {
                    /* Save the next entry in case this one is deleted */
                    SDL_HintWatch *next = entry->next;
                    entry->callback(entry->userdata, name, hint->value, value);
                    entry = next;
                }
                SDL_free(hint->value);
                hint->value = value ? SDL_strdup(value) : NULL;
            }
            hint->priority = priority;
            return SDL_TRUE;
        }
    }

    /* Couldn't find the hint, add a new one */
    hint = (SDL_Hint *)SDL_malloc(sizeof(*hint));
    if (!hint) {
        return SDL_FALSE;
    }
    hint->name = SDL_strdup(name);
    hint->value = value ? SDL_strdup(value) : NULL;
    hint->priority = priority;
    hint->callbacks = NULL;
    hint->next = SDL_hints;
    SDL_hints = hint;
    return SDL_TRUE;
}

SDL_bool
SDL_SetHint(const char *name, const char *value)
{
    return SDL_SetHintWithPriority(name, value, SDL_HINT_NORMAL);
}

const char *
SDL_GetHint(const char *name)
{
    const char *env;
    SDL_Hint *hint;

    env = SDL_getenv(name);
    for (hint = SDL_hints; hint; hint = hint->next) {
        if (SDL_strcmp(name, hint->name) == 0) {
            if (!env || hint->priority == SDL_HINT_OVERRIDE) {
                return hint->value;
            }
            break;
        }
    }
    return env;
}

SDL_bool
SDL_GetHintBoolean(const char *name, SDL_bool default_value)
{
    const char *hint = SDL_GetHint(name);
    if (!hint) {
        return default_value;
    }
    if (*hint == '0' || SDL_strcasecmp(hint, "false") == 0) {
        return SDL_FALSE;
    }
    return SDL_TRUE;
}

void
SDL_AddHintCallback(const char *name, SDL_HintCallback callback, void *userdata)
{
    SDL_Hint *hint;
    SDL_HintWatch *entry;
    const char *value;

    if (!name || !*name) {
        SDL_InvalidParamError("name");
        return;
    }
    if (!callback) {
        SDL_InvalidParamError("callback");
        return;
    }

    SDL_DelHintCallback(name, callback, userdata);

    entry = (SDL_HintWatch *)SDL_malloc(sizeof(*entry));
    if (!entry) {
        SDL_OutOfMemory();
        return;
    }
    entry->callback = callback;
    entry->userdata = userdata;

    for (hint = SDL_hints; hint; hint = hint->next) {
        if (SDL_strcmp(name, hint->name) == 0) {
            break;
        }
    }
    if (!hint) {
        /* Need to add a hint entry for this watcher */
        hint = (SDL_Hint *)SDL_malloc(sizeof(*hint));
        if (!hint) {
            SDL_OutOfMemory();
            SDL_free(entry);
            return;
        }
        hint->name = SDL_strdup(name);
        hint->value = NULL;
        hint->priority = SDL_HINT_DEFAULT;
        hint->callbacks = NULL;
        hint->next = SDL_hints;
        SDL_hints = hint;
    }

    /* Add it to the callbacks for this hint */
    entry->next = hint->callbacks;
    hint->callbacks = entry;

    /* Now call it with the current value */
    value = SDL_GetHint(name);
    callback(userdata, name, value, value);
}

void
SDL_DelHintCallback(const char *name, SDL_HintCallback callback, void *userdata)
{
    SDL_Hint *hint;
    SDL_HintWatch *entry, *prev;

    for (hint = SDL_hints; hint; hint = hint->next) {
        if (SDL_strcmp(name, hint->name) == 0) {
            prev = NULL;
            for (entry = hint->callbacks; entry; entry = entry->next) {
                if (callback == entry->callback && userdata == entry->userdata) {
                    if (prev) {
                        prev->next = entry->next;
                    } else {
                        hint->callbacks = entry->next;
                    }
                    SDL_free(entry);
                    break;
                }
                prev = entry;
            }
            return;
        }
    }
}

void SDL_ClearHints(void)
{
    SDL_Hint *hint;
    SDL_HintWatch *entry;

    while (SDL_hints) {
        hint = SDL_hints;
        SDL_hints = hint->next;

        SDL_free(hint->name);
        SDL_free(hint->value);
        for (entry = hint->callbacks; entry; ) {
            SDL_HintWatch *freeable = entry;
            entry = entry->next;
            SDL_free(freeable);
        }
        SDL_free(hint);
    }
}

/* vi: set ts=4 sw=4 expandtab: */

/*
  Simple DirectMedia Layer
  Copyright (C) 1997-2017 Sam Lantinga <slouken@libsdl.org>

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.
*/

#include "./SDL_internal.h"
#include "SDL.h"
#include "./SDL_dataqueue.h"
#include "SDL_assert.h"

typedef struct SDL_DataQueuePacket
{
    size_t datalen;  /* bytes currently in use in this packet. */
    size_t startpos;  /* bytes currently consumed in this packet. */
    struct SDL_DataQueuePacket *next;  /* next item in linked list. */
    Uint8 data[SDL_VARIABLE_LENGTH_ARRAY];  /* packet data */
} SDL_DataQueuePacket;

struct SDL_DataQueue
{
    SDL_DataQueuePacket *head; /* device fed from here. */
    SDL_DataQueuePacket *tail; /* queue fills to here. */
    SDL_DataQueuePacket *pool; /* these are unused packets. */
    size_t packet_size;   /* size of new packets */
    size_t queued_bytes;  /* number of bytes of data in the queue. */
};

static void
SDL_FreeDataQueueList(SDL_DataQueuePacket *packet)
{
    while (packet) {
        SDL_DataQueuePacket *next = packet->next;
        SDL_free(packet);
        packet = next;
    }
}


/* this all expects that you managed thread safety elsewhere. */

SDL_DataQueue *
SDL_NewDataQueue(const size_t _packetlen, const size_t initialslack)
{
    SDL_DataQueue *queue = (SDL_DataQueue *) SDL_malloc(sizeof (SDL_DataQueue));

    if (!queue) {
        SDL_OutOfMemory();
        return NULL;
    } else {
        const size_t packetlen = _packetlen ? _packetlen : 1024;
        const size_t wantpackets = (initialslack + (packetlen - 1)) / packetlen;
        size_t i;

        SDL_zerop(queue);
        queue->packet_size = packetlen;

        for (i = 0; i < wantpackets; i++) {
            SDL_DataQueuePacket *packet = (SDL_DataQueuePacket *) SDL_malloc(sizeof (SDL_DataQueuePacket) + packetlen);
            if (packet) { /* don't care if this fails, we'll deal later. */
                packet->datalen = 0;
                packet->startpos = 0;
                packet->next = queue->pool;
                queue->pool = packet;
            }
        }
    }

    return queue;
}

void
SDL_FreeDataQueue(SDL_DataQueue *queue)
{
    if (queue) {
        SDL_FreeDataQueueList(queue->head);
        SDL_FreeDataQueueList(queue->pool);
        SDL_free(queue);
    }
}

void
SDL_ClearDataQueue(SDL_DataQueue *queue, const size_t slack)
{
    const size_t packet_size = queue ? queue->packet_size : 1;
    const size_t slackpackets = (slack + (packet_size-1)) / packet_size;
    SDL_DataQueuePacket *packet;
    SDL_DataQueuePacket *prev = NULL;
    size_t i;

    if (!queue) {
        return;
    }

    packet = queue->head;

    /* merge the available pool and the current queue into one list. */
    if (packet) {
        queue->tail->next = queue->pool;
    } else {
        packet = queue->pool;
    }

    /* Remove the queued packets from the device. */
    queue->tail = NULL;
    queue->head = NULL;
    queue->queued_bytes = 0;
    queue->pool = packet;

    /* Optionally keep some slack in the pool to reduce malloc pressure. */
    for (i = 0; packet && (i < slackpackets); i++) {
        prev = packet;
        packet = packet->next;
    }

    if (prev) {
        prev->next = NULL;
    } else {
        queue->pool = NULL;
    }

    SDL_FreeDataQueueList(packet);  /* free extra packets */
}

static SDL_DataQueuePacket *
AllocateDataQueuePacket(SDL_DataQueue *queue)
{
    SDL_DataQueuePacket *packet;

    SDL_assert(queue != NULL);

    packet = queue->pool;
    if (packet != NULL) {
        /* we have one available in the pool. */
        queue->pool = packet->next;
    } else {
        /* Have to allocate a new one! */
        packet = (SDL_DataQueuePacket *) SDL_malloc(sizeof (SDL_DataQueuePacket) + queue->packet_size);
        if (packet == NULL) {
            return NULL;
        }
    }

    packet->datalen = 0;
    packet->startpos = 0;
    packet->next = NULL;
                
    SDL_assert((queue->head != NULL) == (queue->queued_bytes != 0));
    if (queue->tail == NULL) {
        queue->head = packet;
    } else {
        queue->tail->next = packet;
    }
    queue->tail = packet;
    return packet;
}


int
SDL_WriteToDataQueue(SDL_DataQueue *queue, const void *_data, const size_t _len)
{
    size_t len = _len;
    const Uint8 *data = (const Uint8 *) _data;
    const size_t packet_size = queue ? queue->packet_size : 0;
    SDL_DataQueuePacket *orighead;
    SDL_DataQueuePacket *origtail;
    size_t origlen;
    size_t datalen;

    if (!queue) {
        return SDL_InvalidParamError("queue");
    }

    orighead = queue->head;
    origtail = queue->tail;
    origlen = origtail ? origtail->datalen : 0;

    while (len > 0) {
        SDL_DataQueuePacket *packet = queue->tail;
        SDL_assert(!packet || (packet->datalen <= packet_size));
        if (!packet || (packet->datalen >= packet_size)) {
            /* tail packet missing or completely full; we need a new packet. */
            packet = AllocateDataQueuePacket(queue);
            if (!packet) {
                /* uhoh, reset so we've queued nothing new, free what we can. */
                if (!origtail) {
                    packet = queue->head;  /* whole queue. */
                } else {
                    packet = origtail->next;  /* what we added to existing queue. */
                    origtail->next = NULL;
                    origtail->datalen = origlen;
                }
                queue->head = orighead;
                queue->tail = origtail;
                queue->pool = NULL;

                SDL_FreeDataQueueList(packet);  /* give back what we can. */
                return SDL_OutOfMemory();
            }
        }

        datalen = SDL_min(len, packet_size - packet->datalen);
        SDL_memcpy(packet->data + packet->datalen, data, datalen);
        data += datalen;
        len -= datalen;
        packet->datalen += datalen;
        queue->queued_bytes += datalen;
    }

    return 0;
}

size_t
SDL_ReadFromDataQueue(SDL_DataQueue *queue, void *_buf, const size_t _len)
{
    size_t len = _len;
    Uint8 *buf = (Uint8 *) _buf;
    Uint8 *ptr = buf;
    SDL_DataQueuePacket *packet;

    if (!queue) {
        return 0;
    }

    while ((len > 0) && ((packet = queue->head) != NULL)) {
        const size_t avail = packet->datalen - packet->startpos;
        const size_t cpy = SDL_min(len, avail);
        SDL_assert(queue->queued_bytes >= avail);

        SDL_memcpy(ptr, packet->data + packet->startpos, cpy);
        packet->startpos += cpy;
        ptr += cpy;
        queue->queued_bytes -= cpy;
        len -= cpy;

        if (packet->startpos == packet->datalen) {  /* packet is done, put it in the pool. */
            queue->head = packet->next;
            SDL_assert((packet->next != NULL) || (packet == queue->tail));
            packet->next = queue->pool;
            queue->pool = packet;
        }
    }

    SDL_assert((queue->head != NULL) == (queue->queued_bytes != 0));

    if (queue->head == NULL) {
        queue->tail = NULL;  /* in case we drained the queue entirely. */
    }

    return (size_t) (ptr - buf);
}

size_t
SDL_CountDataQueue(SDL_DataQueue *queue)
{
    return queue ? queue->queued_bytes : 0;
}

void *
SDL_ReserveSpaceInDataQueue(SDL_DataQueue *queue, const size_t len)
{
    SDL_DataQueuePacket *packet;

    if (!queue) {
        SDL_InvalidParamError("queue");
        return NULL;
    } else if (len == 0) {
        SDL_InvalidParamError("len");
        return NULL;
    } else if (len > queue->packet_size) {
        SDL_SetError("len is larger than packet size");
        return NULL;
    }

    packet = queue->head;
    if (packet) {
        const size_t avail = queue->packet_size - packet->datalen;
        if (len <= avail) {  /* we can use the space at end of this packet. */
            void *retval = packet->data + packet->datalen;
            packet->datalen += len;
            queue->queued_bytes += len;
            return retval;
        }
    }

    /* Need a fresh packet. */
    packet = AllocateDataQueuePacket(queue);
    if (!packet) {
        SDL_OutOfMemory();
        return NULL;
    }

    packet->datalen = len;
    queue->queued_bytes += len;
    return packet->data;
}

/* vi: set ts=4 sw=4 expandtab: */

