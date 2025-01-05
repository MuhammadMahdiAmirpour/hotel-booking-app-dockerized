import { describe, test, expect, vi } from 'vitest'
import { render, screen, fireEvent, act } from '@testing-library/react'
import '@testing-library/jest-dom'
import RoomSearch from '../../components/common/RoomSearch'

vi.mock('../../components/utils/ApiFunctions', () => ({
    getAvailableRooms: vi.fn(),
    getRoomTypes: vi.fn().mockResolvedValue([
        'SINGLE',
        'DOUBLE',
        'SUITE',
        'DELUXE'
    ])
}))

describe('RoomSearch Component', () => {
    test('handles room type selection', async () => {
        await act(async () => {
            render(<RoomSearch />)
        })

        const roomTypeSelect = screen.getByRole('combobox')

        await act(async () => {
            fireEvent.change(roomTypeSelect, { target: { value: 'SINGLE' } })
        })

        expect(roomTypeSelect.value).toBe('SINGLE')
    })
})
